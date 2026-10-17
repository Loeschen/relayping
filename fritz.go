package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FRITZ!Box-Anbindung über die offiziellen Schnittstellen von AVM:
//   - UPnP-IGD (ohne Passwort, sofern „Statusinformationen über UPnP übertragen“ an ist):
//     Verbindungsstatus, Verbindungsdauer, Leitungsgeschwindigkeit, aktuelle Datenrate, Byte-Zähler
//   - TR-064 (mit FRITZ!Box-Benutzer und Passwort, optional): Laufzeit der Box (Neustarts),
//     Modell und FRITZ!OS-Version, Ersatz für den Verbindungsstatus, wenn UPnP aus ist
// RelayPing fragt die Box direkt vom PC aus ab. Klappt das nicht (etwa weil der PC-Verkehr
// durch den VPN-Tunnel geht), fragt es über den verbundenen Router (curl) – dessen eigener
// Verkehr geht direkt ins Netz der FRITZ!Box.
// Es wird nur gelesen, nie etwas an der FRITZ!Box verändert.

var fritzNoDirect = os.Getenv("RELAYPING_FRITZ_NODIRECT") == "1"

type FritzStatus struct {
	Enabled   bool    `json:"enabled"`
	OK        bool    `json:"ok"`
	Error     string  `json:"error,omitempty"`
	Hint      string  `json:"hint,omitempty"`
	Via       string  `json:"via,omitempty"` // pc, router
	Host      string  `json:"host"`
	Model     string  `json:"model,omitempty"`
	Firmware  string  `json:"firmware,omitempty"`
	Access    string  `json:"access,omitempty"` // DSL, Ethernet, X_AVM-DE_Fiber …
	Link      string  `json:"link,omitempty"`   // Up, Down
	Conn      string  `json:"conn,omitempty"`   // Connected, Connecting, Disconnected …
	ConnSince int64   `json:"conn_since,omitempty"`
	LastError string  `json:"last_error,omitempty"`
	MaxDown   uint64  `json:"max_down,omitempty"` // bit/s laut Leitung
	MaxUp     uint64  `json:"max_up,omitempty"`
	HaveRate  bool    `json:"have_rate"`
	RateDown  float64 `json:"rate_down"` // Byte/s
	RateUp    float64 `json:"rate_up"`
	HaveBytes bool    `json:"have_bytes"`
	TotalRX   uint64  `json:"-"`
	TotalTX   uint64  `json:"-"`
	TodayRX   uint64  `json:"today_rx"`
	TodayTX   uint64  `json:"today_tx"`
	MonthRX   uint64  `json:"month_rx"`
	MonthTX   uint64  `json:"month_tx"`
	Since     int64   `json:"since,omitempty"` // seit wann gezählt wird
	Auth      string  `json:"auth"`            // aus, ok, fehler
	AuthError string  `json:"auth_error,omitempty"`
	User      string  `json:"user,omitempty"`
	HasPass   bool    `json:"has_pass"`
	BootTime  int64   `json:"boot_time,omitempty"`
	Checked   int64   `json:"checked"`
}

type fritzSvc struct{ Type, URL string }

type fritzUsage struct {
	LastRX uint64               `json:"last_rx"`
	LastTX uint64               `json:"last_tx"`
	Have   bool                 `json:"have"`
	Since  int64                `json:"seit"`
	Days   map[string][2]uint64 `json:"tage"`
}

type Fritz struct {
	app  *App
	mu   sync.Mutex
	st   FritzStatus
	file string
	u    fritzUsage

	via        string
	viaUntil   time.Time
	igd        map[string]fritzSvc // wancommon, wanconn
	tr         map[string]fritzSvc // deviceinfo, lansec, wancommon, wanconn
	discovered time.Time
	lastSlow   time.Time
	lastSave   time.Time
	wake       chan struct{}
}

func newFritz(a *App, file string) *Fritz {
	f := &Fritz{app: a, file: file, wake: make(chan struct{}, 1)}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &f.u)
	}
	if f.u.Days == nil {
		f.u.Days = map[string][2]uint64{}
	}
	return f
}

func (f *Fritz) State() FritzStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.st
	c := f.app.store.Get()
	st.Enabled, st.Host, st.HasPass = c.FritzOn, c.FritzHost, c.FritzPass != ""
	if st.User == "" {
		st.User = c.FritzUser
	}
	if !c.FritzOn {
		return FritzStatus{Enabled: false, Host: c.FritzHost, User: c.FritzUser, HasPass: st.HasPass}
	}
	return st
}

// Wake löst sofort eine neue Abfrage aus (z. B. nach geänderten Einstellungen).
func (f *Fritz) Wake() {
	f.mu.Lock()
	f.discovered = time.Time{}
	f.via = ""
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *Fritz) Run() {
	for !f.app.quitting() {
		if f.app.store.Get().FritzOn {
			f.Poll()
		}
		select {
		case <-f.app.quit:
			f.save()
			return
		case <-f.wake:
		case <-time.After(5 * time.Second):
		}
	}
}

// ---------- Adresse ----------

var reFritzHost = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}(:[0-9]{1,5})?$`)

func fritzBase(h string) (string, error) {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(strings.TrimPrefix(h, "http://"), "https://")
	h = strings.TrimSuffix(h, "/")
	if !reFritzHost.MatchString(h) {
		return "", errors.New("ungültige Adresse")
	}
	host, port := h, "49000"
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		host, port = h[:i], h[i+1:]
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", errors.New("ungültiger Port")
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

// ---------- Transport ----------

type fritzCred struct{ User, Pass string }

func (f *Fritz) cred() *fritzCred {
	c := f.app.store.Get()
	if c.FritzPass == "" {
		return nil
	}
	pw, err := unprotectSecret(c.FritzPass)
	if err != nil || pw == "" {
		return nil
	}
	f.mu.Lock()
	u := f.st.User
	f.mu.Unlock()
	if c.FritzUser != "" {
		u = c.FritzUser
	}
	return &fritzCred{User: u, Pass: pw}
}

// request: GET (action == "") oder SOAP-POST. Liefert HTTP-Status und Antwort.
func (f *Fritz) request(path, svcType, action string, cred *fritzCred) (int, string, error) {
	base, err := fritzBase(f.app.store.Get().FritzHost)
	if err != nil {
		return 0, "", err
	}
	body := ""
	if action != "" {
		body = `<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` +
			action + ` xmlns:u="` + svcType + `"></u:` + action + `></s:Body></s:Envelope>`
	}
	f.mu.Lock()
	via := f.via
	if time.Now().After(f.viaUntil) {
		via = ""
	}
	f.mu.Unlock()
	order := []string{"pc", "router"}
	if via == "router" {
		order = []string{"router", "pc"}
	}
	if fritzNoDirect {
		order = []string{"router"}
	}
	var lastErr error
	for _, v := range order {
		var code int
		var resp string
		var err error
		if v == "pc" {
			code, resp, err = fritzDirect(base, path, svcType, action, body, cred)
		} else {
			if ok, _, _ := f.app.router.State(); !ok {
				continue
			}
			code, resp, err = f.viaRouter(base, path, svcType, action, body, cred)
		}
		if err == nil {
			f.mu.Lock()
			if f.via != v {
				f.via = v
			}
			f.viaUntil = time.Now().Add(10 * time.Minute)
			f.mu.Unlock()
			return code, resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("nicht erreichbar")
	}
	return 0, "", lastErr
}

func fritzDirect(base, path, svcType, action, body string, cred *fritzCred) (int, string, error) {
	cl := &http.Client{Timeout: 4 * time.Second}
	mk := func(authz string) *http.Request {
		var req *http.Request
		if action == "" {
			req, _ = http.NewRequest(http.MethodGet, base+path, nil)
		} else {
			req, _ = http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
			req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
			req.Header.Set("SOAPACTION", svcType+"#"+action)
		}
		req.Header.Set("User-Agent", "RelayPing/"+version)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		return req
	}
	resp, err := cl.Do(mk(""))
	if err != nil {
		return 0, "", err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized && cred != nil {
		method := http.MethodPost
		if action == "" {
			method = http.MethodGet
		}
		authz, err := digestAuth(resp.Header.Get("WWW-Authenticate"), method, path, cred.User, cred.Pass)
		if err != nil {
			return resp.StatusCode, string(b), nil
		}
		resp, err = cl.Do(mk(authz))
		if err != nil {
			return 0, "", err
		}
		b, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}
	return resp.StatusCode, string(b), nil
}

// digestAuth berechnet die HTTP-Digest-Anmeldung (RFC 2617, MD5, qop=auth), wie sie TR-064 verlangt.
func digestAuth(challenge, method, uri, user, pass string) (string, error) {
	cb := make([]byte, 8)
	_, _ = rand.Read(cb)
	return digestAuthC(challenge, method, uri, user, pass, hex.EncodeToString(cb))
}

func digestAuthC(challenge, method, uri, user, pass, cnonce string) (string, error) {
	c, ok := strings.CutPrefix(strings.TrimSpace(challenge), "Digest ")
	if !ok {
		return "", errors.New("keine Digest-Anmeldung")
	}
	p := map[string]string{}
	for _, m := range regexp.MustCompile(`(\w+)=("([^"]*)"|[^,\s]*)`).FindAllStringSubmatch(c, -1) {
		v := m[2]
		if strings.HasPrefix(v, `"`) {
			v = m[3]
		}
		p[strings.ToLower(m[1])] = v
	}
	if p["nonce"] == "" {
		return "", errors.New("kein nonce")
	}
	if a := strings.ToUpper(p["algorithm"]); a != "" && a != "MD5" {
		return "", errors.New("Algorithmus nicht unterstützt: " + a)
	}
	h := func(s string) string { x := md5.Sum([]byte(s)); return hex.EncodeToString(x[:]) }
	ha1 := h(user + ":" + p["realm"] + ":" + pass)
	ha2 := h(method + ":" + uri)
	nc := "00000001"
	var resp, extra string
	if strings.Contains(p["qop"], "auth") {
		resp = h(ha1 + ":" + p["nonce"] + ":" + nc + ":" + cnonce + ":auth:" + ha2)
		extra = fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, nc, cnonce)
	} else {
		resp = h(ha1 + ":" + p["nonce"] + ":" + ha2)
	}
	s := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=MD5, response="%s"%s`,
		user, p["realm"], p["nonce"], uri, resp, extra)
	if p["opaque"] != "" {
		s += fmt.Sprintf(`, opaque="%s"`, p["opaque"])
	}
	return s, nil
}

const fritzRouterScript = `command -v curl >/dev/null 2>&1 || { echo "RPHTTP nocurl"; exit 0; }
T=/tmp/rpfb.$$; umask 077; : > "$T"
%s
curl -s -m 6 -K "$T" %s -w '\nRPHTTP %%{http_code}\n' '%s' %s
rm -f "$T"
`

func curlQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func (f *Fritz) viaRouter(base, path, svcType, action, body string, cred *fritzCred) (int, string, error) {
	url := base + path
	if strings.ContainsAny(url, "'\n ") {
		return 0, "", errors.New("ungültige Adresse")
	}
	cfg := ""
	opts := ""
	if cred != nil {
		if strings.ContainsAny(cred.User+cred.Pass, "\n\r") || strings.Contains(cred.Pass, "RPCFG") {
			return 0, "", errors.New("ungültiges Passwort")
		}
		cfg = "cat > \"$T\" <<'RPCFG'\nuser = \"" + curlQuote(cred.User) + ":" + curlQuote(cred.Pass) + "\"\nRPCFG"
		opts = "--digest"
	}
	data := ""
	if action != "" {
		if strings.ContainsAny(svcType+action, "'\n") {
			return 0, "", errors.New("ungültige Anfrage")
		}
		opts += ` -H 'Content-Type: text/xml; charset="utf-8"' -H 'SOAPACTION: ` + svcType + "#" + action + `'`
		data = "--data-binary @- <<'RPBODY'\n" + body + "\nRPBODY"
	}
	out, err := f.app.router.Run(fmt.Sprintf(fritzRouterScript, cfg, opts, url, data), 15*time.Second)
	if err != nil && !strings.Contains(out, "RPHTTP") {
		return 0, "", err
	}
	i := strings.LastIndex(out, "\nRPHTTP ")
	if i < 0 {
		if strings.HasPrefix(out, "RPHTTP ") {
			i = -1
		} else {
			return 0, "", errors.New("keine Antwort")
		}
	}
	tail := strings.TrimSpace(out[i+1:])
	resp := ""
	if i > 0 {
		resp = out[:i]
	}
	code, _ := strconv.Atoi(strings.TrimPrefix(tail, "RPHTTP "))
	if strings.Contains(tail, "nocurl") {
		return 0, "", errors.New("auf dem Router fehlt curl")
	}
	if code == 0 {
		return 0, "", errors.New("FRITZ!Box antwortet dem Router nicht")
	}
	return code, resp, nil
}

// ---------- XML ----------

type fritzDesc struct {
	Services []fritzSvc
	Model    string
	Friendly string
	Display  string
}

func parseFritzDesc(s string) fritzDesc {
	var d fritzDesc
	dec := xml.NewDecoder(strings.NewReader(s))
	dec.Strict = false
	var stack []string
	var cur fritzSvc
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if t.Name.Local == "service" {
				cur = fritzSvc{}
			}
		case xml.EndElement:
			if t.Name.Local == "service" && cur.Type != "" && cur.URL != "" {
				d.Services = append(d.Services, cur)
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			v := strings.TrimSpace(string(t))
			if v == "" {
				continue
			}
			switch stack[len(stack)-1] {
			case "serviceType":
				cur.Type = v
			case "controlURL":
				cur.URL = v
			case "modelName":
				if d.Model == "" {
					d.Model = v
				}
			case "friendlyName":
				if d.Friendly == "" {
					d.Friendly = v
				}
			case "Display":
				if d.Display == "" {
					d.Display = v
				}
			}
		}
	}
	return d
}

func (d fritzDesc) find(part string) (fritzSvc, bool) {
	for _, s := range d.Services {
		if strings.Contains(s.Type, part) {
			return s, true
		}
	}
	return fritzSvc{}, false
}

// parseSOAP liefert alle Ausgabewerte (New…) oder den SOAP-Fehler.
func parseSOAP(s string) (map[string]string, error) {
	out := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader(s))
	dec.Strict = false
	var name string
	var buf bytes.Buffer
	fault := false
	var faultText []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "Fault" {
				fault = true
			}
			name = t.Name.Local
			buf.Reset()
		case xml.CharData:
			buf.Write(t)
		case xml.EndElement:
			if t.Name.Local == name {
				v := strings.TrimSpace(buf.String())
				if strings.HasPrefix(name, "New") {
					out[name] = v
				}
				if fault && (name == "errorCode" || name == "errorDescription" || name == "faultstring") && v != "" {
					faultText = append(faultText, v)
				}
			}
			name = ""
		}
	}
	if fault {
		return out, errors.New("FRITZ!Box: " + strings.Join(faultText, " "))
	}
	return out, nil
}

func (f *Fritz) call(svc fritzSvc, action string, cred *fritzCred) (map[string]string, error) {
	code, body, err := f.request(svc.URL, svc.Type, action, cred)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errTransport, err)
	}
	if code == http.StatusUnauthorized {
		return nil, errAuth
	}
	vals, err := parseSOAP(body)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("HTTP %d", code)
	}
	return vals, nil
}

var (
	errAuth      = errors.New("auth")
	errTransport = errors.New("FRITZ!Box nicht erreichbar")
)

func atou(s string) uint64 { v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64); return v }

// ---------- Abfrage ----------

func (f *Fritz) discover() error {
	a := f.app
	code, body, err := f.request("/igddesc.xml", "", "", nil)
	igd := map[string]fritzSvc{}
	var d fritzDesc
	reachable := err == nil
	if err == nil && code == 200 {
		d = parseFritzDesc(body)
		if s, ok := d.find("WANCommonInterfaceConfig:"); ok {
			igd["wancommon"] = s
		}
		if s, ok := d.find("WANIPConnection:"); ok {
			igd["wanconn"] = s
		} else if s, ok := d.find("WANPPPConnection:"); ok {
			igd["wanconn"] = s
		}
	}
	tr := map[string]fritzSvc{}
	code2, body2, err2 := f.request("/tr64desc.xml", "", "", nil)
	reachable = reachable || err2 == nil
	var d2 fritzDesc
	if err2 == nil && code2 == 200 {
		d2 = parseFritzDesc(body2)
		for key, part := range map[string]string{"deviceinfo": "dslforum-org:service:DeviceInfo:", "lansec": "dslforum-org:service:LANConfigSecurity:",
			"wancommon": "dslforum-org:service:WANCommonInterfaceConfig:", "wanppp": "dslforum-org:service:WANPPPConnection:", "wanip": "dslforum-org:service:WANIPConnection:"} {
			if s, ok := d2.find(part); ok {
				tr[key] = s
			}
		}
	}
	if !reachable {
		return fmt.Errorf(a.tr("FRITZ!Box unter %s nicht erreichbar (%v)", "FRITZ!Box not reachable at %s (%v)"), a.store.Get().FritzHost, err)
	}
	if len(igd) == 0 && len(tr) == 0 {
		return errors.New(a.tr("Unter dieser Adresse antwortet keine FRITZ!Box (keine UPnP/TR-064-Beschreibung)", "No FRITZ!Box answers at this address (no UPnP/TR-064 description)"))
	}
	f.mu.Lock()
	f.igd, f.tr = igd, tr
	f.discovered = time.Now()
	model := d2.Model
	if model == "" {
		model = d.Model
	}
	if model == "" {
		model = d2.Friendly
	}
	if model != "" {
		f.st.Model = model
	}
	if d2.Display != "" {
		f.st.Firmware = d2.Display
	}
	f.mu.Unlock()
	return nil
}

// Poll fragt die FRITZ!Box einmal ab.
func (f *Fritz) Poll() FritzStatus {
	a := f.app
	now := time.Now()
	f.mu.Lock()
	need := f.igd == nil || time.Since(f.discovered) > 30*time.Minute
	f.mu.Unlock()
	fail := func(err error) FritzStatus {
		f.mu.Lock()
		f.st.OK, f.st.Error, f.st.Checked = false, err.Error(), now.Unix()
		f.st.HaveRate = false
		f.igd = nil
		f.mu.Unlock()
		st := f.State()
		a.broadcast("fritz", st)
		return st
	}
	if need {
		if err := f.discover(); err != nil {
			return fail(err)
		}
	}
	f.mu.Lock()
	igd, tr := f.igd, f.tr
	slow := time.Since(f.lastSlow) > time.Minute || f.st.Checked == 0
	prev := f.st
	f.mu.Unlock()
	st := prev
	st.OK, st.Error, st.Hint, st.Checked = true, "", "", now.Unix()
	cred := f.cred()
	if s, ok := igd["wancommon"]; ok {
		if v, err := f.call(s, "GetAddonInfos", nil); err == nil {
			st.RateDown, st.RateUp = float64(atou(v["NewByteReceiveRate"])), float64(atou(v["NewByteSendRate"]))
			st.HaveRate = true
			rx, tx := atou(v["NewX_AVM_DE_TotalBytesReceived64"]), atou(v["NewX_AVM_DE_TotalBytesSent64"])
			if rx == 0 && tx == 0 {
				rx, tx = atou(v["NewTotalBytesReceived"]), atou(v["NewTotalBytesSent"])
			}
			if _, has := v["NewX_AVM_DE_TotalBytesReceived64"]; has || rx > 0 {
				st.TotalRX, st.TotalTX, st.HaveBytes = rx, tx, true
			}
		} else if errors.Is(err, errTransport) {
			return fail(err)
		}
		if slow {
			if v, err := f.call(s, "GetCommonLinkProperties", nil); err == nil {
				st.Access, st.Link = v["NewWANAccessType"], v["NewPhysicalLinkStatus"]
				st.MaxDown, st.MaxUp = atou(v["NewLayer1DownstreamMaxBitRate"]), atou(v["NewLayer1UpstreamMaxBitRate"])
			}
		}
	}
	if s, ok := igd["wanconn"]; ok {
		if v, err := f.call(s, "GetStatusInfo", nil); err == nil {
			st.Conn, st.LastError = v["NewConnectionStatus"], v["NewLastConnectionError"]
			if up := int64(atou(v["NewUptime"])); up > 0 && st.Conn == "Connected" {
				st.ConnSince = now.Unix() - up
			} else {
				st.ConnSince = 0
			}
		}
	}
	if len(igd) == 0 {
		st.Hint = a.tr("In der FRITZ!Box ist „Statusinformationen über UPnP übertragen“ aus (Heimnetz → Netzwerk → Netzwerkeinstellungen). Mit dieser Einstellung zeigt RelayPing Datenrate und Verbrauch.",
			"“Transmit status information over UPnP” is off in the FRITZ!Box (Home Network → Network → Network Settings). With it, RelayPing shows data rate and usage.")
	}
	// TR-064 mit Anmeldung
	if cred == nil {
		st.Auth, st.AuthError = "aus", ""
	} else if slow {
		if cred.User == "" {
			if s, ok := tr["lansec"]; ok {
				if v, err := f.call(s, "X_AVM-DE_GetUserList", nil); err == nil {
					cred.User = pickFritzUser(v["NewX_AVM-DE_UserList"])
				}
			}
		}
		st.User = cred.User
		if s, ok := tr["deviceinfo"]; ok {
			v, err := f.call(s, "GetInfo", cred)
			switch {
			case err == nil:
				st.Auth, st.AuthError = "ok", ""
				if up := int64(atou(v["NewUpTime"])); up > 0 {
					st.BootTime = now.Unix() - up
				}
				if v["NewModelName"] != "" {
					st.Model = v["NewModelName"]
				}
				if v["NewSoftwareVersion"] != "" {
					st.Firmware = v["NewSoftwareVersion"]
				}
			case errors.Is(err, errAuth):
				st.Auth, st.AuthError = "fehler", a.tr("Anmeldung abgelehnt – Benutzer und Passwort prüfen. Der Benutzer braucht in der FRITZ!Box das Recht „FRITZ!Box Einstellungen“.", "Login rejected – check user and password. The user needs the “FRITZ!Box settings” permission.")
			default:
				st.Auth, st.AuthError = "fehler", err.Error()
			}
		}
		// Ersatz, wenn UPnP-Status aus ist
		if _, ok := igd["wanconn"]; !ok && st.Auth == "ok" {
			for _, k := range []string{"wanppp", "wanip"} {
				if s, ok := tr[k]; ok {
					if v, err := f.call(s, "GetInfo", cred); err == nil && v["NewConnectionStatus"] != "" {
						st.Conn, st.LastError = v["NewConnectionStatus"], v["NewLastConnectionError"]
						if up := int64(atou(v["NewUptime"])); up > 0 && st.Conn == "Connected" {
							st.ConnSince = now.Unix() - up
						}
						break
					}
				}
			}
		}
		if _, ok := igd["wancommon"]; !ok && st.Auth == "ok" {
			if s, ok := tr["wancommon"]; ok {
				if v, err := f.call(s, "GetCommonLinkProperties", cred); err == nil {
					st.Access, st.Link = v["NewWANAccessType"], v["NewPhysicalLinkStatus"]
					st.MaxDown, st.MaxUp = atou(v["NewLayer1DownstreamMaxBitRate"]), atou(v["NewLayer1UpstreamMaxBitRate"])
				}
			}
		}
	}
	f.mu.Lock()
	if slow {
		f.lastSlow = now
	}
	st.Via = f.via
	if st.HaveBytes {
		f.u.add(st.TotalRX, st.TotalTX, now)
	}
	st.TodayRX, st.TodayTX, st.MonthRX, st.MonthTX = f.u.sums(now)
	st.Since = f.u.Since
	f.st = st
	save := time.Since(f.lastSave) > 10*time.Minute
	f.mu.Unlock()
	if save {
		f.save()
	}
	a.outages.ObserveFritz(st, now)
	out := f.State()
	a.broadcast("fritz", out)
	return out
}

func pickFritzUser(list string) string {
	// NewX_AVM-DE_UserList ist selbst XML: <List><Username last_user="1">fritz1234</Username>…</List>
	list = html.UnescapeString(list)
	if m := regexp.MustCompile(`<Username[^>]*last_user="1"[^>]*>([^<]+)</Username>`).FindStringSubmatch(list); m != nil {
		return strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`<Username[^>]*>([^<]+)</Username>`).FindStringSubmatch(list); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func (f *Fritz) save() {
	f.mu.Lock()
	b, err := json.Marshal(f.u)
	f.lastSave = time.Now()
	f.mu.Unlock()
	if err == nil {
		writeAtomic(f.file, b)
	}
}

// add zählt die Differenz der Byte-Zähler zum heutigen Tag. Fällt ein Zähler
// (Neustart der Box), zählt der neue Stand ab null.
func (u *fritzUsage) add(rx, tx uint64, now time.Time) {
	if u.Days == nil {
		u.Days = map[string][2]uint64{}
	}
	if !u.Have {
		u.LastRX, u.LastTX, u.Have = rx, tx, true
		if u.Since == 0 {
			u.Since = now.Unix()
		}
		return
	}
	d := func(cur, last uint64) uint64 {
		if cur >= last {
			return cur - last
		}
		return cur
	}
	drx, dtx := d(rx, u.LastRX), d(tx, u.LastTX)
	u.LastRX, u.LastTX = rx, tx
	if drx > 1e13 || dtx > 1e13 { // unplausibel
		return
	}
	k := now.Format("2006-01-02")
	v := u.Days[k]
	v[0] += drx
	v[1] += dtx
	u.Days[k] = v
	if len(u.Days) > 400 {
		var ks []string
		for x := range u.Days {
			ks = append(ks, x)
		}
		sort.Strings(ks)
		for _, x := range ks[:len(ks)-400] {
			delete(u.Days, x)
		}
	}
}

func (u *fritzUsage) sums(now time.Time) (trx, ttx, mrx, mtx uint64) {
	today, month := now.Format("2006-01-02"), now.Format("2006-01")
	for k, v := range u.Days {
		if k == today {
			trx, ttx = v[0], v[1]
		}
		if strings.HasPrefix(k, month) {
			mrx += v[0]
			mtx += v[1]
		}
	}
	return
}

// MonthUsage: Verbrauch laut FRITZ!Box in einem Monat ("2006-01").
func (f *Fritz) MonthUsage(m string) (rx, tx uint64, days int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.u.Days {
		if strings.HasPrefix(k, m) {
			rx += v[0]
			tx += v[1]
			days++
		}
	}
	return
}

// SetCredentials speichert Adresse, Benutzer und (verschlüsselt) Passwort.
func (f *Fritz) Configure(on bool, host, user, pass string, keepPass bool) error {
	a := f.app
	if _, err := fritzBase(host); err != nil {
		return errors.New(a.tr("Ungültige FRITZ!Box-Adresse", "Invalid FRITZ!Box address"))
	}
	if user != "" && !regexp.MustCompile(`^[A-Za-z0-9._@\-]{1,64}$`).MatchString(user) {
		return errors.New(a.tr("Ungültiger Benutzername", "Invalid user name"))
	}
	if strings.ContainsAny(pass, "\r\n") || len(pass) > 128 {
		return errors.New(a.tr("Ungültiges Passwort", "Invalid password"))
	}
	enc := ""
	if keepPass {
		enc = a.store.Get().FritzPass
	} else if pass != "" {
		var err error
		if enc, err = protectSecret(pass); err != nil {
			return fmt.Errorf(a.tr("Passwort konnte nicht verschlüsselt werden: %v", "Could not encrypt the password: %v"), err)
		}
	}
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "http://"), "/")
	err := a.store.Update(func(c *Config) {
		c.FritzOn, c.FritzHost, c.FritzUser, c.FritzPass = on, host, user, enc
	})
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.st = FritzStatus{}
	f.mu.Unlock()
	f.Wake()
	return nil
}

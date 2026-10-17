package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	reIface = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)
	reHost  = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}$`)
	// uci-Abschnitt, z. B. "cfg0a1b2c" oder "@wireguard_wg0[0]"
	reUCISection = regexp.MustCompile(`^@?[A-Za-z0-9_]{1,40}(\[[0-9]{1,2}\])?$`)

	errHostKeyChanged = errors.New("hostkey-changed")
	errNoKey          = errors.New("no-key")
	errNotConnected   = errors.New("not-connected")
)

// locErr trägt einen übersetzten Text und behält den Grundfehler für errors.Is.
type locErr struct {
	base error
	msg  string
}

func (e *locErr) Error() string { return e.msg }
func (e *locErr) Unwrap() error { return e.base }

func (r *Router) hostKeyErr() error {
	return &locErr{errHostKeyChanged, r.app.tr(
		"Der SSH-Schlüssel des Routers hat sich geändert. Falls du den Router zurückgesetzt oder getauscht hast: in den Einstellungen „Router-Zugang zurücksetzen“.",
		"The router's SSH key has changed. If you reset or replaced the router: Settings → “Reset router access”.")}
}

func (r *Router) notConnected() error {
	return &locErr{errNotConnected, r.app.tr("nicht mit dem Router verbunden", "not connected to the router")}
}

type Tunnel struct {
	Iface     string  `json:"iface"`
	IP        string  `json:"ip"`
	PubKey    string  `json:"-"`
	Host      string  `json:"host"`
	City      string  `json:"city"`
	CC        string  `json:"cc"`
	Handshake int64   `json:"handshake"`     // Unix-Zeit des letzten Handshakes (Router-Uhr)
	HSAge     int64   `json:"handshake_age"` // Sekunden seit dem letzten Handshake, -1 = nie
	RX        uint64  `json:"rx"`
	TX        uint64  `json:"tx"`
	RXRate    float64 `json:"rx_rate"` // Byte/s
	TXRate    float64 `json:"tx_rate"`
	// aus der GL.iNet-Konfiguration (falls lesbar)
	Name      string `json:"name,omitempty"`
	TunnelID  int    `json:"tunnel_id,omitempty"`
	CanSwitch bool   `json:"can_switch"`
	Probe     int    `json:"probe"` // Ping durch den Tunnel: 1 ok, 0 fehlgeschlagen, -1 unbekannt
}

type RouterInfo struct {
	Platform  string    `json:"platform"` // glinet, openwrt, asus oder leer (unbekannt)
	Firmware  string    `json:"firmware,omitempty"`
	Merlin    bool      `json:"merlin,omitempty"`
	WAN       string    `json:"wan"`
	FastPing  bool      `json:"fastping"`
	Model     string    `json:"model"`
	Tunnels   []Tunnel  `json:"tunnels"`
	HasWG     bool      `json:"has_wg"`
	Checked   time.Time `json:"checked"`
	Load1     float64   `json:"load1"`
	NProc     int       `json:"nproc"`
	MemTotal  int64     `json:"mem_total_kb"`
	MemAvail  int64     `json:"mem_avail_kb"`
	TempC     float64   `json:"temp_c"`
	UptimeS   float64   `json:"uptime_s"`
	RouterNow int64     `json:"-"`
	BootTime  int64     `json:"boot_time"`
	WANRX     uint64    `json:"wan_rx"`
	WANTX     uint64    `json:"wan_tx"`
	HaveWANCt bool      `json:"have_wan_counter"`
	WANOK     int       `json:"wan_ok"` // 1 ok, 0 keine Antwort, -1 unbekannt
	// OpenWrt/Asus: Tunnel-Einstellungen für den Server-Wechsel ohne GL.iNet-Schnittstelle
	Native   map[string]NativeTun `json:"-"`
	DefIface string               `json:"-"` // Schnittstelle der Standardroute des Routers
}

type Router struct {
	app *App

	mu           sync.Mutex
	client       *ssh.Client
	connected    bool
	lastErr      string
	info         RouterInfo
	newHostKey   ssh.PublicKey
	reconnecting bool
	prevTR       map[string][3]float64 // iface -> rx, tx, zeit
	gl           *GLState
	needLogin    bool // Schlüssel wird nicht mehr angenommen (z. B. Asus nach Neustart)
	glProbe      int  // OpenWrt erkannt: antwortet trotzdem die GL.iNet-Schnittstelle? 0 offen, 1 ja, -1 nein
}

// NeedLogin: Der Router lehnt den gespeicherten Schlüssel ab – einmal neu mit Passwort anmelden.
func (r *Router) NeedLogin() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.needLogin
}

// PublicKey liefert den öffentlichen Schlüssel von RelayPing (zum Eintragen in der Router-Oberfläche).
func (r *Router) PublicKey() string {
	sg, err := r.signer()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sg.PublicKey()))) + " relayping"
}

func (r *Router) keyFile() string { return r.app.store.File("relayping.key") }

func (r *Router) HasKey() bool {
	_, err := os.Stat(r.keyFile())
	return err == nil
}

func (r *Router) State() (bool, string, RouterInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected, r.lastErr, r.info
}

func (r *Router) hostKeyCB(_ string, _ net.Addr, key ssh.PublicKey) error {
	stored := strings.TrimSpace(r.app.store.Get().HostKey)
	got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if stored == "" {
		r.newHostKey = key
		return nil
	}
	if stored != got {
		return r.hostKeyErr()
	}
	return nil
}

func fingerprint(authorized string) string {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(k.Marshal())
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

func (r *Router) dial(auth []ssh.AuthMethod) (*ssh.Client, error) {
	c := r.app.store.Get()
	if !reHost.MatchString(c.RouterHost) {
		return nil, errors.New(r.app.tr("Ungültige Router-Adresse", "Invalid router address"))
	}
	cfg := &ssh.ClientConfig{
		User:            c.RouterUser,
		Auth:            auth,
		HostKeyCallback: r.hostKeyCB,
		Timeout:         6 * time.Second,
	}
	r.newHostKey = nil
	addr := net.JoinHostPort(c.RouterHost, strconv.Itoa(c.RouterPort))
	cl, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			r.mu.Lock()
			r.needLogin = true
			r.mu.Unlock()
		}
		return nil, r.friendlyErr(err)
	}
	r.mu.Lock()
	r.needLogin = false
	r.mu.Unlock()
	if r.newHostKey != nil {
		hk := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(r.newHostKey)))
		_ = r.app.store.Update(func(c *Config) { c.HostKey = hk })
		r.newHostKey = nil
	}
	return cl, nil
}

func (r *Router) friendlyErr(err error) error {
	s := err.Error()
	switch {
	case errors.Is(err, errHostKeyChanged):
		return r.hostKeyErr()
	case strings.Contains(s, "unable to authenticate"):
		return errors.New(r.app.tr("Anmeldung abgelehnt – Benutzer und Passwort prüfen (GL.iNet: „root“ und das Admin-Passwort; Asus: Name und Passwort der Router-Oberfläche)",
			"Login rejected – check user and password (GL.iNet: “root” and the admin password; Asus: the web interface's user name and password)"))
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "no route") || strings.Contains(s, "connection refused"):
		return fmt.Errorf(r.app.tr("Router nicht erreichbar (%v). Adresse prüfen und ob SSH aktiv ist",
			"Router not reachable (%v). Check the address and whether SSH is enabled"), err)
	}
	return err
}

func (r *Router) signer() (ssh.Signer, error) {
	b, err := os.ReadFile(r.keyFile())
	if err != nil {
		return nil, errNoKey
	}
	return ssh.ParsePrivateKey(b)
}

// ConnectKey verbindet mit dem gespeicherten Schlüssel.
func (r *Router) ConnectKey() error {
	sg, err := r.signer()
	if err != nil {
		return err
	}
	cl, err := r.dial([]ssh.AuthMethod{ssh.PublicKeys(sg)})
	if err != nil {
		r.setErr(err)
		return err
	}
	r.attach(cl)
	return nil
}

// ConnectPassword meldet sich einmalig mit Passwort an und hinterlegt einen Schlüssel.
func (r *Router) ConnectPassword(pw string) error {
	ki := ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
		a := make([]string, len(qs))
		for i := range a {
			a[i] = pw
		}
		return a, nil
	})
	cl, err := r.dial([]ssh.AuthMethod{ssh.Password(pw), ki})
	if err != nil {
		r.setErr(err)
		return err
	}
	if err := r.installKey(cl); err != nil {
		cl.Close()
		r.setErr(err)
		return fmt.Errorf(r.app.tr("Anmeldung ok, aber Schlüssel konnte nicht hinterlegt werden: %w", "Login ok, but the key could not be installed: %w"), err)
	}
	cl.Close()
	// Gegenprobe: klappt der Schlüssel?
	if err := r.ConnectKey(); err != nil {
		return fmt.Errorf(r.app.tr("Schlüssel hinterlegt, aber Anmeldung damit fehlgeschlagen: %w", "Key installed, but logging in with it failed: %w"), err)
	}
	return nil
}

// installKeyCmd hinterlegt den öffentlichen Schlüssel – das Einzige, was RelayPing beim
// Anmelden auf dem Router ablegt. Router-Einstellungen (uci, nvram) bleiben unberührt.
//   - OpenWrt/GL.iNet: /etc/dropbear/authorized_keys
//   - Asus: /root/.ssh/authorized_keys. Die Asus-Firmware schreibt diese Datei beim Neustart
//     aus ihrer Einstellung neu; dauerhaft wird der Schlüssel erst, wenn man ihn selbst in der
//     Asus-Oberfläche (Administration → System → Autorisierte Schlüssel) einträgt.
//   - sonst: ~/.ssh/authorized_keys
const installKeyCmd = `umask 077; L='@KEY@'
if [ -f /etc/openwrt_release ] && [ -d /etc/dropbear ]; then f=/etc/dropbear/authorized_keys
elif command -v nvram >/dev/null 2>&1 && [ -n "$(nvram get productid 2>/dev/null)" ]; then
  mkdir -p /root/.ssh 2>/dev/null; f=/root/.ssh/authorized_keys; [ -d /root/.ssh ] || { mkdir -p "$HOME/.ssh"; f="$HOME/.ssh/authorized_keys"; }
else mkdir -p "$HOME/.ssh"; f="$HOME/.ssh/authorized_keys"; fi
touch "$f"; grep -qxF "$L" "$f" || echo "$L" >> "$f"; echo OK`

func (r *Router) installKey(cl *ssh.Client) error {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " relayping"
	cmd := strings.ReplaceAll(installKeyCmd, "@KEY@", line)
	out, err := runOn(cl, cmd, 15*time.Second)
	if err != nil || !strings.Contains(out, "OK") {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(out))
	}
	block, err := ssh.MarshalPrivateKey(key, "relayping")
	if err != nil {
		return err
	}
	return os.WriteFile(r.keyFile(), pem.EncodeToMemory(block), 0o600)
}

func (r *Router) attach(cl *ssh.Client) {
	r.mu.Lock()
	if r.client != nil {
		r.client.Close()
	}
	r.client = cl
	r.connected = true
	r.lastErr = ""
	r.glProbe = 0
	r.mu.Unlock()
	go r.keepalive(cl)
	r.Refresh()
	r.app.onConnected()
}

func (r *Router) setErr(err error) {
	r.mu.Lock()
	r.lastErr = err.Error()
	r.mu.Unlock()
	r.app.pushState()
}

func (r *Router) Disconnect() {
	r.mu.Lock()
	if r.client != nil {
		r.client.Close()
		r.client = nil
	}
	r.connected = false
	r.mu.Unlock()
}

func (r *Router) keepalive(cl *ssh.Client) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		r.mu.Lock()
		cur := r.client
		r.mu.Unlock()
		if cur != cl {
			return
		}
		errc := make(chan error, 1)
		go func() { _, _, err := cl.SendRequest("keepalive@openssh.com", true, nil); errc <- err }()
		var err error
		select {
		case err = <-errc:
		case <-time.After(8 * time.Second):
			err = errors.New(r.app.tr("Zeitüberschreitung", "timeout"))
		}
		if err != nil {
			r.lost(cl, fmt.Errorf(r.app.tr("Verbindung zum Router verloren (%v)", "Lost connection to the router (%v)"), err))
			return
		}
	}
}

func (r *Router) lost(cl *ssh.Client, err error) {
	r.mu.Lock()
	if r.client != cl {
		r.mu.Unlock()
		return
	}
	cl.Close()
	r.client = nil
	r.connected = false
	r.lastErr = err.Error()
	start := !r.reconnecting
	r.reconnecting = true
	r.mu.Unlock()
	r.app.pushState()
	if start {
		go r.reconnectLoop()
	}
}

// EnsureReconnect startet die Wiederverbindung im Hintergrund (z. B. Router beim Start noch nicht erreichbar).
func (r *Router) EnsureReconnect() {
	r.mu.Lock()
	if r.reconnecting || r.connected {
		r.mu.Unlock()
		return
	}
	r.reconnecting = true
	r.mu.Unlock()
	go r.reconnectLoop()
}

func (r *Router) reconnectLoop() {
	defer func() { r.mu.Lock(); r.reconnecting = false; r.mu.Unlock() }()
	for i := 0; ; i++ {
		time.Sleep(time.Duration(min(5+i*2, 30)) * time.Second)
		if r.app.quitting() {
			return
		}
		if err := r.ConnectKey(); err == nil {
			return
		} else if errors.Is(err, errNoKey) || errors.Is(err, errHostKeyChanged) || r.NeedLogin() {
			r.app.pushState()
			return
		}
	}
}

// Session liefert eine neue SSH-Sitzung oder einen Fehler, wenn getrennt.
func (r *Router) Session() (*ssh.Session, error) {
	r.mu.Lock()
	cl := r.client
	r.mu.Unlock()
	if cl == nil {
		return nil, r.notConnected()
	}
	s, err := cl.NewSession()
	if err != nil {
		r.lost(cl, err)
		return nil, err
	}
	return s, nil
}

func (r *Router) Run(cmd string, timeout time.Duration) (string, error) {
	r.mu.Lock()
	cl := r.client
	r.mu.Unlock()
	if cl == nil {
		return "", r.notConnected()
	}
	return runOn(cl, cmd, timeout)
}

func runOn(cl *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	s, err := cl.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	var buf bytes.Buffer
	s.Stdout = &buf
	s.Stderr = io.Discard
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(timeout):
		s.Close()
		return buf.String(), errors.New("Zeitüberschreitung")
	}
}

const infoCmd = `P=""
if [ -f /etc/glversion ] || grep -qi '^gl' /tmp/sysinfo/model 2>/dev/null; then P=glinet
elif [ -f /etc/openwrt_release ]; then P=openwrt
elif command -v nvram >/dev/null 2>&1 && [ -n "$(nvram get productid 2>/dev/null)" ]; then P=asus; fi
echo "PLAT=$P"
W=""
if [ "$P" = asus ]; then W=$(nvram get wan0_gw_ifname 2>/dev/null); [ -z "$W" ] && W=$(nvram get wan0_ifname 2>/dev/null); fi
if [ -z "$W" ] && command -v ubus >/dev/null 2>&1 && command -v jsonfilter >/dev/null 2>&1; then W=$(ubus call network.interface.wan status 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null); fi
[ -z "$W" ] && W=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
echo "WAN=$W"
ping -c 1 -i 0.2 -W 1 127.0.0.1 >/dev/null 2>&1 && echo "FASTPING=1"
command -v wg >/dev/null 2>&1 && echo "HASWG=1"
wg show all endpoints 2>/dev/null | sed 's/^/EP /'
wg show all latest-handshakes 2>/dev/null | sed 's/^/HS /'
wg show all transfer 2>/dev/null | sed 's/^/TR /'
echo "LOAD $(cat /proc/loadavg 2>/dev/null)"
echo "NPROC $(grep -c ^processor /proc/cpuinfo 2>/dev/null)"
awk '/^MemTotal:|^MemAvailable:/{print "MEM", $1, $2}' /proc/meminfo 2>/dev/null
for z in /sys/class/thermal/thermal_zone*/temp; do [ -r "$z" ] && echo "TEMP $(cat "$z")"; done
echo "UP $(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "NOW $(date +%s)"
echo "MODEL=$(cat /tmp/sysinfo/model 2>/dev/null)"
if [ "$P" = asus ]; then
  echo "MODEL=ASUS $(nvram get productid 2>/dev/null)"
  echo "FW=$(nvram get firmver 2>/dev/null).$(nvram get buildno 2>/dev/null)_$(nvram get extendno 2>/dev/null)"
  echo "THIRD=$(nvram get 3rd-party 2>/dev/null)"
  for n in 1 2 3 4 5; do echo "WGC $n $(nvram get wgc${n}_enable 2>/dev/null) $(nvram get wgc${n}_desc 2>/dev/null)"; done
fi
if [ "$P" = openwrt ]; then
  echo "FW=$(. /etc/openwrt_release 2>/dev/null; echo "$DISTRIB_DESCRIPTION")"
  uci -q show network 2>/dev/null | sed -n 's/^network\.\([^=.]*\)=wireguard_\(.*\)$/UPEER \2 \1/p'
fi
if [ "$P" = glinet ]; then echo "FW=$(cat /etc/glversion 2>/dev/null)"; fi
echo "DEFRT $(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')"
echo "BTIME $(awk '/^btime/{print $2}' /proc/stat 2>/dev/null)"
if [ -n "$W" ]; then sed -n "s/^ *$W: *//p" /proc/net/dev 2>/dev/null | awk '{print "NETDEV", $1, $9}'; fi
for i in $(wg show interfaces 2>/dev/null); do ( if ping -c 1 -W 2 -I "$i" 10.64.0.1 >/dev/null 2>&1; then echo "TP $i 1"; else echo "TP $i 0"; fi ) & done
( O=""; [ -n "$W" ] && O="-I $W"; if ping -c 1 -W 2 $O 1.1.1.1 >/dev/null 2>&1 || ping -c 1 -W 2 $O 9.9.9.9 >/dev/null 2>&1; then echo "WANOK 1"; else echo "WANOK 0"; fi ) &
wait
`

// parseInfo wertet die Ausgabe von infoCmd aus (ohne Seiteneffekte, testbar).
func parseInfo(out string) RouterInfo {
	inf := RouterInfo{WANOK: -1}
	probes := map[string]bool{}
	hs := map[string]int64{}
	tr := map[string][2]uint64{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(l, "WAN="):
			w := strings.TrimPrefix(l, "WAN=")
			if reIface.MatchString(w) && !strings.HasPrefix(w, "wg") && !strings.HasPrefix(w, "tun") {
				inf.WAN = w
			}
		case l == "FASTPING=1":
			inf.FastPing = true
		case l == "HASWG=1":
			inf.HasWG = true
		case strings.HasPrefix(l, "MODEL="):
			if m := strings.TrimSpace(strings.TrimPrefix(l, "MODEL=")); m != "" && m != "ASUS" {
				inf.Model = m
			}
		case strings.HasPrefix(l, "PLAT="):
			switch p := strings.TrimPrefix(l, "PLAT="); p {
			case "glinet", "openwrt", "asus":
				inf.Platform = p
			}
		case strings.HasPrefix(l, "FW="):
			inf.Firmware = strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "FW=")), "._'\"")
		case strings.HasPrefix(l, "THIRD="):
			inf.Merlin = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(l, "THIRD=")), "merlin")
		case f[0] == "WGC" && len(f) >= 3:
			n, err := strconv.Atoi(f[1])
			if err != nil || n < 1 || n > 5 {
				continue
			}
			if inf.Native == nil {
				inf.Native = map[string]NativeTun{}
			}
			inf.Native["wgc"+f[1]] = NativeTun{Unit: n, Enabled: f[2] == "1", Desc: strings.Join(f[3:], " ")}
		case f[0] == "UPEER" && len(f) == 3:
			if !reIface.MatchString(f[1]) || !reUCISection.MatchString(f[2]) {
				continue
			}
			if inf.Native == nil {
				inf.Native = map[string]NativeTun{}
			}
			nt := inf.Native[f[1]]
			nt.Peers++
			nt.Section, nt.Enabled = f[2], true
			inf.Native[f[1]] = nt
		case f[0] == "DEFRT" && len(f) >= 2:
			if reIface.MatchString(f[1]) {
				inf.DefIface = f[1]
			}
		case f[0] == "EP" && len(f) >= 4:
			host, _, err := net.SplitHostPort(f[3])
			if err != nil {
				continue
			}
			inf.Tunnels = append(inf.Tunnels, Tunnel{Iface: f[1], PubKey: f[2], IP: host, HSAge: -1, Probe: -1})
		case f[0] == "HS" && len(f) >= 4:
			v, _ := strconv.ParseInt(f[3], 10, 64)
			hs[f[1]+" "+f[2]] = v
		case f[0] == "TR" && len(f) >= 5:
			rx, _ := strconv.ParseUint(f[3], 10, 64)
			tx, _ := strconv.ParseUint(f[4], 10, 64)
			tr[f[1]+" "+f[2]] = [2]uint64{rx, tx}
		case f[0] == "LOAD" && len(f) >= 2:
			inf.Load1, _ = strconv.ParseFloat(f[1], 64)
		case f[0] == "NPROC" && len(f) >= 2:
			inf.NProc, _ = strconv.Atoi(f[1])
		case f[0] == "MEM" && len(f) >= 3:
			v, _ := strconv.ParseInt(f[2], 10, 64)
			if f[1] == "MemTotal:" {
				inf.MemTotal = v
			} else {
				inf.MemAvail = v
			}
		case f[0] == "TEMP" && len(f) >= 2:
			v, _ := strconv.ParseFloat(f[1], 64)
			if v > 1000 {
				v /= 1000
			}
			if v > inf.TempC && v < 150 {
				inf.TempC = v
			}
		case f[0] == "UP" && len(f) >= 2:
			inf.UptimeS, _ = strconv.ParseFloat(f[1], 64)
		case f[0] == "BTIME" && len(f) >= 2:
			inf.BootTime, _ = strconv.ParseInt(f[1], 10, 64)
		case f[0] == "NETDEV" && len(f) >= 3:
			inf.WANRX, _ = strconv.ParseUint(f[1], 10, 64)
			inf.WANTX, _ = strconv.ParseUint(f[2], 10, 64)
			inf.HaveWANCt = true
		case f[0] == "TP" && len(f) >= 3:
			probes[f[1]] = f[2] == "1"
		case f[0] == "WANOK" && len(f) >= 2:
			if f[1] == "1" {
				inf.WANOK = 1
			} else {
				inf.WANOK = 0
			}
		case f[0] == "NOW" && len(f) >= 2:
			inf.RouterNow, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	for i := range inf.Tunnels {
		t := &inf.Tunnels[i]
		k := t.Iface + " " + t.PubKey
		if v, ok := hs[k]; ok && v > 0 {
			t.Handshake = v
			if inf.RouterNow > 0 {
				t.HSAge = inf.RouterNow - v
			}
		}
		if v, ok := tr[k]; ok {
			t.RX, t.TX = v[0], v[1]
		}
		if p, ok := probes[t.Iface]; ok {
			t.Probe = 0
			if p {
				t.Probe = 1
			}
		}
	}
	if inf.Platform == "asus" && inf.Firmware != "" {
		inf.Firmware = strings.TrimSuffix(inf.Firmware, "_")
		if inf.Merlin {
			inf.Firmware += " (Asuswrt-Merlin)"
		}
	}
	return inf
}

// Refresh liest WAN-Schnittstelle, aktive Tunnel und Router-Zustand neu ein.
func (r *Router) Refresh() {
	out, err := r.Run(infoCmd, 15*time.Second)
	if err != nil && out == "" {
		return
	}
	inf := parseInfo(out)
	if inf.Platform == "openwrt" || inf.Platform == "" {
		// GL.iNet-Firmware ist OpenWrt – sicherheitshalber an der GL.iNet-Schnittstelle erkennen,
		// damit Tunnel nie an der GL.iNet-Verwaltung vorbei umgestellt werden
		r.mu.Lock()
		probe := r.glProbe
		r.mu.Unlock()
		if probe == 0 {
			var raw json.RawMessage
			probe = -1
			if r.RPC("vpn-client", "get_tunnel", nil, &raw) == nil {
				probe = 1
			}
			r.mu.Lock()
			r.glProbe = probe
			r.mu.Unlock()
		}
		if probe == 1 {
			inf.Platform = "glinet"
		}
	}
	now := float64(time.Now().UnixMilli()) / 1000
	r.mu.Lock()
	if r.prevTR == nil {
		r.prevTR = map[string][3]float64{}
	}
	gl := r.gl
	for i := range inf.Tunnels {
		t := &inf.Tunnels[i]
		if rl, ok := r.app.relays.Match(t.IP, t.PubKey); ok {
			t.Host, t.City, t.CC = rl.Host, rl.City, rl.CountryCode
		}
		if p, ok := r.prevTR[t.Iface]; ok && now > p[2] && float64(t.RX) >= p[0] && float64(t.TX) >= p[1] {
			dt := now - p[2]
			t.RXRate = (float64(t.RX) - p[0]) / dt
			t.TXRate = (float64(t.TX) - p[1]) / dt
		}
		r.prevTR[t.Iface] = [3]float64{float64(t.RX), float64(t.TX), now}
		if inf.Platform == "openwrt" || inf.Platform == "asus" {
			r.app.nativeTunnel(&inf, t)
		} else if gl != nil {
			if gt, ok := gl.ByIface(t.Iface); ok {
				t.Name, t.TunnelID, t.CanSwitch = gt.Name, gt.TunnelID, gl.OK
			}
		}
	}
	inf.Checked = time.Now()
	r.info = inf
	r.mu.Unlock()
	r.app.pushState()
}

func (r *Router) PingIfaceOpt() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.info.WAN != "" {
		return "-I " + r.info.WAN
	}
	return ""
}

// Forget löscht Schlüssel und gemerkten Host-Key (z. B. nach Router-Reset).
func (r *Router) Forget() {
	r.Disconnect()
	os.Remove(r.keyFile())
	_ = r.app.store.Update(func(c *Config) { c.HostKey = "" })
	r.mu.Lock()
	r.info = RouterInfo{}
	r.lastErr = ""
	r.gl = nil
	r.mu.Unlock()
}

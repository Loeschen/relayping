package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ländersperren: Ländervergleich (welches Land außer Deutschland ist am
// schnellsten erreichbar und hat keine Sperrpflicht) und Sperr-Check
// (ist eine Domain in Deutschland per DNS gesperrt, ist sie über den Tunnel
// erreichbar?).

// ---------- Rechtslage Erwachsenen-Seiten ----------

type AdultRule struct {
	Status string `json:"status"` // frei, pflicht, teilweise, geplant
	DE     string `json:"de"`
	EN     string `json:"en"`
}

// Stand: Juni 2026 (Quellen: Proton Age-Verification-Übersicht, Euronews, netzpolitik.org).
// Kann sich jederzeit ändern – die Oberfläche weist darauf hin.
const adultRulesAsOf = "Juni 2026"

var adultRules = map[string]AdultRule{
	"de": {"pflicht", "Altersprüfung Pflicht, Provider sperren große Seiten per DNS (KJM)", "Age checks required, ISPs DNS-block major sites (KJM)"},
	"fr": {"pflicht", "Altersprüfung Pflicht (Arcom), große Anbieter haben sich zurückgezogen", "Age checks required (Arcom), major providers withdrew"},
	"it": {"pflicht", "Altersprüfung Pflicht (AGCOM)", "Age checks required (AGCOM)"},
	"gb": {"pflicht", "Altersprüfung Pflicht (Online Safety Act)", "Age checks required (Online Safety Act)"},
	"es": {"pflicht", "Altersprüfung gesetzlich vorgeschrieben", "Age checks required by law"},
	"sk": {"pflicht", "Altersprüfung für Video-Plattformen", "Age checks for video platforms"},
	"ie": {"teilweise", "Altersprüfung für Plattformen mit Sitz in Irland", "Age checks for platforms based in Ireland"},
	"pl": {"geplant", "Gesetz zur Altersprüfung geplant", "Age-check law planned"},
	"se": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"dk": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"nl": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"no": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"fi": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"ch": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"at": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"be": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"cz": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
	"lu": {"frei", "keine Altersprüfungs-Pflicht bekannt", "no age-check requirement known"},
}

// Kandidaten für den Ländervergleich: Europa ohne Deutschland.
var geoCandidates = []string{"nl", "dk", "se", "no", "fi", "ch", "at", "be", "lu", "cz", "pl", "fr", "it", "es", "gb", "ie", "sk"}

// ---------- Ländervergleich ----------

type CountryBest struct {
	CC       string    `json:"cc"`
	Host     string    `json:"host"`
	City     string    `json:"city"`
	Avg      float64   `json:"avg"`
	Jitter   float64   `json:"jitter"`
	Loss     int       `json:"loss"`
	Measured int       `json:"measured"`
	T        time.Time `json:"t"`
}

type CountryRow struct {
	CC        string       `json:"cc"`
	Name      string       `json:"name"`
	Servers   int          `json:"servers"`
	Profiles  int          `json:"profiles"`
	Best      *CountryBest `json:"best,omitempty"`
	Rule      AdultRule    `json:"rule"`
	RuleText  string       `json:"rule_text"`
	Recommend bool         `json:"recommend"`
}

type GeoState struct {
	Rows      []CountryRow `json:"rows"`
	AsOf      string       `json:"rules_as_of"`
	Comparing bool         `json:"comparing"`
	Updated   time.Time    `json:"updated"`
}

type Geo struct {
	app   *App
	mu    sync.Mutex
	file  string
	best  map[string]CountryBest
	await bool // Ländervergleich läuft über den Scanner
}

func newGeo(a *App, file string) *Geo {
	g := &Geo{app: a, file: file, best: map[string]CountryBest{}}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &g.best)
	}
	if g.best == nil {
		g.best = map[string]CountryBest{}
	}
	return g
}

// Ingest übernimmt die besten Server je Land aus einer abgeschlossenen Messung.
func (g *Geo) Ingest(results []ScanResult, at time.Time) {
	if g == nil {
		return
	}
	per := map[string][]ScanResult{}
	for _, r := range results {
		per[r.CountryCode] = append(per[r.CountryCode], r)
	}
	g.mu.Lock()
	for cc, rs := range per {
		sortResults(rs)
		b := rs[0]
		if b.Recv == 0 {
			continue
		}
		g.best[cc] = CountryBest{CC: cc, Host: b.Host, City: b.City, Avg: round1(b.Avg), Jitter: round1(b.Jitter), Loss: b.Loss, Measured: len(rs), T: at}
	}
	g.await = false
	data, _ := json.MarshalIndent(g.best, "", "  ")
	g.mu.Unlock()
	writeAtomic(g.file, data)
	g.app.broadcast("geo", g.State())
}

// Compare misst alle Kandidaten-Länder (10 Pings je Server).
func (g *Geo) Compare() error {
	var ccs []string
	have := map[string]bool{}
	for _, r := range g.app.relays.All() {
		have[r.CountryCode] = true
	}
	for _, c := range geoCandidates {
		if have[c] {
			ccs = append(ccs, c)
		}
	}
	if err := g.app.scanner.start(ccs, 10, false); err != nil {
		return err
	}
	g.mu.Lock()
	g.await = true
	g.mu.Unlock()
	g.app.broadcast("geo", g.State())
	return nil
}

func (g *Geo) State() GeoState {
	a := g.app
	gl := a.router.GL()
	profiles := map[string]int{}
	if gl != nil {
		for h := range gl.ByName {
			if len(h) > 2 && h[2] == '-' {
				profiles[h[:2]]++
			}
		}
	}
	servers := map[string]int{}
	names := map[string]string{}
	for _, r := range a.relays.All() {
		servers[r.CountryCode]++
		names[r.CountryCode] = r.Country
	}
	g.mu.Lock()
	st := GeoState{AsOf: adultRulesAsOf, Comparing: g.await && a.scanner.State().Running}
	for _, cc := range geoCandidates {
		if servers[cc] == 0 {
			continue
		}
		row := CountryRow{CC: cc, Name: names[cc], Servers: servers[cc], Profiles: profiles[cc], Rule: adultRules[cc]}
		if row.Rule.Status == "" {
			row.Rule = AdultRule{"unbekannt", "Rechtslage nicht hinterlegt", "legal status not on file"}
		}
		row.RuleText = a.tr(row.Rule.DE, row.Rule.EN)
		if b, ok := g.best[cc]; ok {
			bb := b
			row.Best = &bb
			if b.T.After(st.Updated) {
				st.Updated = b.T
			}
		}
		st.Rows = append(st.Rows, row)
	}
	g.mu.Unlock()
	sortCountries(st.Rows)
	for i := range st.Rows {
		if st.Rows[i].Rule.Status == "frei" && st.Rows[i].Best != nil && st.Rows[i].Best.Loss == 0 {
			st.Rows[i].Recommend = true
			break
		}
	}
	return st
}

// sortCountries: gemessene vor ungemessenen, dann Verlust, dann Ping.
func sortCountries(rows []CountryRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i].Best, rows[j].Best
		if (a == nil) != (b == nil) {
			return a != nil
		}
		if a == nil {
			return rows[i].CC < rows[j].CC
		}
		if (a.Loss > 0) != (b.Loss > 0) {
			return a.Loss == 0
		}
		return a.Avg < b.Avg
	})
}

// ---------- Sperr-Check ----------

var reDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`)

func cleanDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#:"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if !reDomain.MatchString(s) {
		return ""
	}
	return s
}

// DomainList liefert die Domainliste eines Tunnels aus der GL.iNet-Konfiguration.
func (g *Geo) DomainList(tunnelID int) (GLTunnel, []string, error) {
	g.app.router.RefreshGL(false)
	gl := g.app.router.GL()
	if gl == nil || !gl.OK {
		return GLTunnel{}, nil, errors.New(g.app.tr("Tunnel-Konfiguration nicht lesbar", "Tunnel configuration not readable"))
	}
	var t GLTunnel
	found := false
	for _, x := range gl.Tunnels {
		to, _ := x.Raw["to"].(map[string]any)
		isDomain := to != nil && to["type"] == "domain"
		if (tunnelID != 0 && x.TunnelID == tunnelID) || (tunnelID == 0 && isDomain && !found) {
			t, found = x, true
		}
	}
	if !found {
		return GLTunnel{}, nil, errors.New(g.app.tr("Kein Tunnel mit Domainliste gefunden", "No tunnel with a domain list found"))
	}
	return t, splitDomains(t), nil
}

func splitDomains(t GLTunnel) []string {
	to, _ := t.Raw["to"].(map[string]any)
	raw, _ := to["domain_list"].(string)
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == ';' || r == '\r' || r == '\t' }) {
		if d := cleanDomain(f); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

type BlockResult struct {
	Domain   string   `json:"domain"`
	DE       string   `json:"de"` // frei, gesperrt, unbekannt
	DEDetail string   `json:"de_detail"`
	VPN      string   `json:"vpn"` // erreichbar, gesperrt, fehler
	HTTP     int      `json:"http"`
	Final    string   `json:"final,omitempty"`
	InList   bool     `json:"in_list"`
	Advice   string   `json:"advice"`
	IPsDE    []string `json:"-"`
	IPsVPN   []string `json:"-"`
}

const blockScript = `W='%s'; IF='%s'
D=$(mktemp -d 2>/dev/null || echo /tmp/rpbc$$); mkdir -p "$D"
one() {
  d="$1"; f="$D/$d"
  { echo "BEGIN $d"
    if [ -n "$W" ]; then nslookup "$d" "$W" 2>&1 | sed 's/^/DE /'; fi
    nslookup "$d" 10.64.0.1 2>&1 | sed 's/^/VPN /'
    if [ -n "$IF" ] && command -v curl >/dev/null 2>&1; then
      echo "HTTP $(curl -s -o /dev/null -L --max-redirs 4 -m 10 --interface "$IF" -A 'Mozilla/5.0' -w '%%{http_code} %%{url_effective}' "https://$d/" 2>/dev/null)"
    fi
    echo "END $d"; } > "$f" 2>&1
}
i=0
for d in %s; do one "$d" & i=$((i+1)); [ $((i %% 8)) -eq 0 ] && wait; done
wait
cat "$D"/* 2>/dev/null; rm -rf "$D"
echo DONE
`

const wanDNSCmd = `W=""
if command -v ubus >/dev/null 2>&1 && command -v jsonfilter >/dev/null 2>&1; then W=$(ubus call network.interface.wan status 2>/dev/null | jsonfilter -e '@["dns-server"][0]' 2>/dev/null); fi
case "$W" in *[!0-9a-fA-F.:]*) W="";; esac
[ -z "$W" ] && W=$(awk '/^nameserver/{print $2; exit}' /tmp/resolv.conf.d/resolv.conf.auto /tmp/resolv.conf.auto 2>/dev/null)
[ -z "$W" ] && W=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="via"){print $(i+1); exit}}')
echo "$W"`

// BlockCheck prüft Domains: DNS beim Provider (über die WAN-Leitung des
// Routers) und Erreichbarkeit über den angegebenen Tunnel.
func (g *Geo) BlockCheck(domains []string, iface string, list []string) ([]BlockResult, string, error) {
	a := g.app
	if iface != "" && !reIface.MatchString(iface) {
		return nil, "", errors.New(a.tr("Ungültige Schnittstelle", "Invalid interface"))
	}
	var ds []string
	seen := map[string]bool{}
	for _, d := range domains {
		if c := cleanDomain(d); c != "" && !seen[c] {
			seen[c] = true
			ds = append(ds, c)
		}
	}
	if len(ds) == 0 {
		return nil, "", errors.New(a.tr("Keine gültige Domain angegeben", "No valid domain given"))
	}
	if len(ds) > 80 {
		ds = ds[:80]
	}
	out, err := a.router.Run(wanDNSCmd, 10*time.Second)
	if err != nil {
		return nil, "", err
	}
	wdns := strings.TrimSpace(out)
	if net.ParseIP(wdns) == nil {
		wdns = ""
	}
	res, err := a.router.Run(fmt.Sprintf(blockScript, wdns, iface, strings.Join(ds, " ")), 120*time.Second)
	if err != nil && !strings.Contains(res, "DONE") {
		return nil, "", err
	}
	inList := map[string]bool{}
	for _, d := range list {
		inList[d] = true
	}
	parsed := parseBlock(res)
	var rs []BlockResult
	for _, d := range ds {
		r := parsed[d]
		r.Domain = d
		r.InList = inList[d] || inListParent(d, inList)
		classify(&r, wdns != "", iface != "")
		r.Advice = a.blockAdvice(r)
		rs = append(rs, r)
	}
	return rs, wdns, nil
}

func inListParent(d string, list map[string]bool) bool {
	for p := d; strings.Contains(p, "."); p = p[strings.Index(p, ".")+1:] {
		if list[p] {
			return true
		}
	}
	return false
}

// parseBlock wertet die Ausgabe von blockScript aus (testbar).
func parseBlock(out string) map[string]BlockResult {
	m := map[string]BlockResult{}
	var cur string
	var r BlockResult
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "BEGIN "):
			cur, r = strings.TrimSpace(l[6:]), BlockResult{}
		case strings.HasPrefix(l, "END "):
			if cur != "" {
				m[cur] = r
			}
			cur = ""
		case cur == "":
		case strings.HasPrefix(l, "DE "), strings.HasPrefix(l, "VPN "):
			de := strings.HasPrefix(l, "DE ")
			body := strings.TrimSpace(l[strings.Index(l, " ")+1:])
			lb := strings.ToLower(body)
			add := func(s string) {
				if de {
					r.DEDetail = strings.TrimSpace(r.DEDetail + " " + s)
				}
			}
			switch {
			case strings.Contains(lb, "nxdomain") || strings.Contains(lb, "can't find") || strings.Contains(lb, "can't resolve"):
				add("NXDOMAIN")
			case strings.Contains(lb, "canonical name ="):
				add("CNAME " + strings.TrimSpace(body[strings.Index(lb, "=")+1:]))
			case strings.HasPrefix(lb, "address") && !strings.Contains(lb, "#53") && !strings.HasSuffix(lb, ":53"):
				// "Address: 1.2.3.4" oder "Address 1: 1.2.3.4 name"
				f := strings.Fields(body)
				for _, x := range f[1:] {
					if ip := net.ParseIP(strings.TrimSuffix(x, ",")); ip != nil {
						if de {
							r.IPsDE = append(r.IPsDE, ip.String())
						} else {
							r.IPsVPN = append(r.IPsVPN, ip.String())
						}
						break
					}
				}
			case strings.Contains(lb, "timed out") || strings.Contains(lb, "no servers could be reached"):
				add("TIMEOUT")
			}
		case strings.HasPrefix(l, "HTTP "):
			f := strings.Fields(l[5:])
			if len(f) > 0 {
				r.HTTP, _ = strconv.Atoi(f[0])
			}
			if len(f) > 1 {
				r.Final = f[1]
			}
		}
	}
	return m
}

// classify bestimmt die Einstufung aus den Rohdaten.
func classify(r *BlockResult, haveDE, haveVPN bool) {
	d := strings.ToLower(r.DEDetail)
	blockedIP := false
	for _, ip := range r.IPsDE {
		if ip == "0.0.0.0" || strings.HasPrefix(ip, "127.") || ip == "::" || ip == "::1" {
			blockedIP = true
		}
	}
	switch {
	case !haveDE:
		r.DE = "unbekannt"
	case strings.Contains(d, "cuii") || strings.Contains(d, "sperr") || strings.Contains(d, "notice") || strings.Contains(d, "kjm") || blockedIP:
		r.DE = "gesperrt"
	case strings.Contains(d, "nxdomain") && len(r.IPsVPN) > 0:
		r.DE = "gesperrt"
	case len(r.IPsDE) > 0:
		r.DE = "frei"
	default:
		r.DE = "unbekannt"
	}
	switch {
	case !haveVPN:
		r.VPN = ""
	case r.HTTP == 451:
		r.VPN = "gesperrt"
	case r.HTTP >= 200 && r.HTTP < 400:
		r.VPN = "erreichbar"
		if f := strings.ToLower(r.Final); strings.Contains(f, "age-verif") || strings.Contains(f, "ageverif") || strings.Contains(f, "verify-age") {
			r.VPN = "altersprüfung"
		}
	case r.HTTP == 403:
		r.VPN = "abgelehnt"
	case r.HTTP == 0:
		r.VPN = "fehler"
	default:
		r.VPN = "erreichbar"
	}
}

func (a *App) blockAdvice(r BlockResult) string {
	switch {
	case r.DE == "gesperrt" && !r.InList:
		return a.tr("In Deutschland gesperrt und nicht in der Domainliste – im GL.iNet-Panel zur Domainliste des Tunnels hinzufügen.", "Blocked in Germany and not on the domain list – add it to the tunnel's domain list in the GL.iNet panel.")
	case r.DE == "gesperrt" && r.InList && r.VPN == "erreichbar":
		return a.tr("In Deutschland gesperrt, läuft über den Tunnel und ist erreichbar.", "Blocked in Germany, routed through the tunnel and reachable.")
	case r.VPN == "gesperrt":
		return a.tr("Auch im Land des Tunnel-Servers gesperrt (HTTP 451) – anderes Land wählen.", "Also blocked in the tunnel server's country (HTTP 451) – choose another country.")
	case r.VPN == "altersprüfung":
		return a.tr("Im Land des Tunnel-Servers wird eine Altersprüfung verlangt – Land aus dem Ländervergleich wählen.", "The tunnel server's country requires an age check – pick a country from the comparison.")
	case r.VPN == "abgelehnt":
		return a.tr("Die Seite lehnt die Mullvad-Adresse ab (HTTP 403) – oft eine VPN-Sperre des Anbieters.", "The site refuses the Mullvad address (HTTP 403) – often a VPN block by the provider.")
	}
	return ""
}

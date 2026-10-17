package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Spiele: Der Router kennt in seiner Verbindungstabelle (conntrack) jede
// Verbindung deiner Geräte. RelayPing sucht darin Spielverbindungen, misst den
// Ping zum Spielserver durch den Tunnel und direkt, und zählt die Pakete pro
// Sekunde, die der Server schickt (≈ Update-/Tickrate).

var conntrackPath = envOr("RELAYPING_CONNTRACK", "/proc/net/nf_conntrack")

type GameFlow struct {
	Key     string  `json:"key"`
	Proto   string  `json:"proto"`
	Client  string  `json:"client"`
	Server  string  `json:"server"`
	CPort   int     `json:"cport"`
	SPort   int     `json:"sport"`
	Game    string  `json:"game"`
	Via     string  `json:"via"`     // tunnel, direkt
	RateIn  float64 `json:"rate_in"` // Pakete/s vom Server
	RateOut float64 `json:"rate_out"`
	BytesIn float64 `json:"bytes_in"` // Byte/s vom Server
	PktsIn  uint64  `json:"-"`
	PktsOut uint64  `json:"-"`
	BIn     uint64  `json:"-"`
	ReplyTo string  `json:"-"`
}

type ctEntry struct {
	proto          string
	src, dst       string
	sport, dport   int
	pkts, bytes    uint64
	rsrc, rdst     string
	rsport, rdport int
	rpkts, rbytes  uint64
	haveCounters   bool
}

// parseConntrack liest eine Zeile aus /proc/net/nf_conntrack.
func parseConntrack(l string) (ctEntry, bool) {
	f := strings.Fields(l)
	var e ctEntry
	if len(f) < 6 || f[0] != "ipv4" {
		return e, false
	}
	e.proto = f[2]
	if e.proto != "udp" && e.proto != "tcp" {
		return e, false
	}
	side := 0
	for _, kv := range f[3:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "src":
			side++
			if side == 1 {
				e.src = v
			} else {
				e.rsrc = v
			}
		case "dst":
			if side <= 1 {
				e.dst = v
			} else {
				e.rdst = v
			}
		case "sport":
			n, _ := strconv.Atoi(v)
			if side <= 1 {
				e.sport = n
			} else {
				e.rsport = n
			}
		case "dport":
			n, _ := strconv.Atoi(v)
			if side <= 1 {
				e.dport = n
			} else {
				e.rdport = n
			}
		case "packets":
			n, _ := strconv.ParseUint(v, 10, 64)
			e.haveCounters = true
			if side <= 1 {
				e.pkts = n
			} else {
				e.rpkts = n
			}
		case "bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			if side <= 1 {
				e.bytes = n
			} else {
				e.rbytes = n
			}
		}
	}
	return e, e.src != "" && e.dst != ""
}

func (e ctEntry) key() string {
	return fmt.Sprintf("%s %s:%d %s:%d", e.proto, e.src, e.sport, e.dst, e.dport)
}

func privateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() ||
		(ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xc0 == 64) // CGNAT
}

// guessGame ordnet bekannte Spiel-Ports zu.
func guessGame(proto string, port int) string {
	in := func(a, b int) bool { return port >= a && port <= b }
	switch {
	case port == 1119 || port == 3724 || in(6112, 6119):
		return "Blizzard (Battle.net, WoW, Heroes, Overwatch …)"
	case in(26400, 26599) && proto == "udp":
		return "Overwatch"
	case in(27015, 27050) || in(27000, 27014):
		return "Steam / Valve (CS2, Dota 2 …)"
	case in(7000, 8000) && proto == "udp":
		return "Riot (Valorant)"
	case in(5000, 5500) && proto == "udp":
		return "League of Legends"
	case in(9000, 9100) && proto == "udp":
		return "Fortnite (Epic)"
	case port == 3074 || in(3478, 3480):
		return "Call of Duty / Konsole"
	case in(30000, 30009) && proto == "udp":
		return "Apex Legends"
	}
	return ""
}

// ignoredPort: Verkehr, der kein Spiel ist (Web, DNS, Video, VPN).
func ignoredPort(proto string, port int) bool {
	switch port {
	case 53, 80, 123, 443, 853, 5353, 1900, 51820, 8080, 8443, 993, 587, 465, 5222, 5223:
		return true
	}
	return false
}

const gameScanScript = `F='%s'
echo "ACCT $(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null)"
L=$(ip -4 -o addr show br-lan 2>/dev/null | awk '{print $4; exit}')
echo "LAN $L"
P=$(echo "$L" | cut -d/ -f1 | cut -d. -f1-3)
[ -n "$P" ] || P='192.168.8'
for n in 1 2; do
  echo "SNAP $n $(cut -d' ' -f1 /proc/uptime)"
  grep -E "^ipv4 +[0-9]+ +(udp|tcp) " "$F" 2>/dev/null | grep "src=$P\." | grep -v ' dport=53 '
  [ $n -eq 1 ] && sleep 2
done
echo DONE
`

type GameScan struct {
	Flows     []GameFlow `json:"flows"`
	Acct      bool       `json:"acct"` // Paketzählung aktiv
	AcctKnown bool       `json:"acct_known"`
	LAN       string     `json:"lan"`
	Note      string     `json:"note,omitempty"`
	Scanned   int64      `json:"scanned"`
}

func (a *App) tunnelAddrs() map[string]string {
	// Tunnel-Adresse (10.x) -> Tunnelname, damit klar ist, ob ein Spiel durch den Tunnel läuft
	out := map[string]string{}
	res, err := a.router.Run(`for i in $(wg show interfaces 2>/dev/null); do echo "$i $(ip -4 -o addr show $i 2>/dev/null | awk '{print $4; exit}')"; done`, 10*time.Second)
	if err != nil {
		return out
	}
	_, _, inf := a.router.State()
	names := map[string]string{}
	for _, t := range inf.Tunnels {
		names[t.Iface] = t.Name
	}
	for _, l := range strings.Split(res, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			ip, _, _ := strings.Cut(f[1], "/")
			n := names[f[0]]
			if n == "" {
				n = f[0]
			}
			out[ip] = n
		}
	}
	return out
}

// ScanGames sucht aktive Spielverbindungen (zwei Momentaufnahmen im Abstand von 2 s).
func (a *App) ScanGames() (GameScan, error) {
	var gs GameScan
	out, err := a.router.Run(fmt.Sprintf(gameScanScript, shellQuote(conntrackPath)), 30*time.Second)
	if err != nil && !strings.Contains(out, "DONE") {
		return gs, err
	}
	gs.Scanned = time.Now().Unix()
	tun := a.tunnelAddrs()
	snaps := [2]map[string]ctEntry{{}, {}}
	var times [2]float64
	cur := -1
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		f := strings.Fields(l)
		switch {
		case len(f) >= 2 && f[0] == "ACCT":
			gs.AcctKnown = true
			gs.Acct = f[1] == "1"
		case len(f) >= 1 && f[0] == "LAN":
			if len(f) > 1 {
				gs.LAN = f[1]
			}
		case len(f) == 3 && f[0] == "SNAP":
			cur, _ = strconv.Atoi(f[1])
			cur--
			if cur >= 0 && cur < 2 {
				times[cur], _ = strconv.ParseFloat(f[2], 64)
			}
		default:
			if cur < 0 || cur > 1 {
				continue
			}
			if e, ok := parseConntrack(l); ok && !privateIP(e.dst) && !ignoredPort(e.proto, e.dport) {
				snaps[cur][e.key()] = e
			}
		}
	}
	dt := times[1] - times[0]
	if dt <= 0 {
		dt = 2
	}
	for k, e := range snaps[1] {
		g := GameFlow{Key: k, Proto: e.proto, Client: e.src, Server: e.dst, CPort: e.sport, SPort: e.dport, Game: guessGame(e.proto, e.dport)}
		if n, ok := tun[e.rdst]; ok {
			g.Via = n
		} else {
			g.Via = "direkt"
		}
		if p, ok := snaps[0][k]; ok && e.haveCounters {
			if e.rpkts >= p.rpkts {
				g.RateIn = round1(float64(e.rpkts-p.rpkts) / dt)
				g.BytesIn = round1(float64(e.rbytes-p.rbytes) / dt)
			}
			if e.pkts >= p.pkts {
				g.RateOut = round1(float64(e.pkts-p.pkts) / dt)
			}
		}
		// Kandidaten: bekannte Spiel-Ports oder UDP mit regelmäßigem Verkehr
		if g.Game == "" && !(e.proto == "udp" && g.RateIn >= 5) {
			continue
		}
		if g.Game == "" {
			g.Game = a.tr("unbekanntes Spiel (UDP)", "unknown game (UDP)")
		}
		gs.Flows = append(gs.Flows, g)
	}
	for _, e := range snaps[1] {
		if e.haveCounters {
			gs.Acct, gs.AcctKnown = true, true // Zähler sind da, also ist die Zählung aktiv
			break
		}
	}
	sort.Slice(gs.Flows, func(i, j int) bool { return gs.Flows[i].RateIn > gs.Flows[j].RateIn })
	if len(gs.Flows) > 20 {
		gs.Flows = gs.Flows[:20]
	}
	switch {
	case gs.AcctKnown && !gs.Acct:
		gs.Note = a.tr("Die Paketzählung des Routers (nf_conntrack_acct) ist aus. RelayPing ändert keine Router-Einstellungen – Spielverbindung und Ping lassen sich trotzdem messen, die Update-Rate aber nicht.",
			"The router's packet accounting (nf_conntrack_acct) is off. RelayPing does not change router settings – the game connection and ping can still be measured, but not the update rate.")
	case len(gs.Flows) == 0:
		gs.Note = a.tr("Keine Spielverbindung gefunden. Starte ein Spiel (am besten eine laufende Runde) und suche erneut.", "No game connection found. Start a game (ideally a running match) and search again.")
	}
	return gs, nil
}

func shellQuote(s string) string { return strings.ReplaceAll(s, "'", "") }

// ---------- Beobachtung einer Spielverbindung ----------

type GameSample struct {
	T   int64   `json:"t"`
	In  float64 `json:"in"` // Pakete/s vom Server
	Out float64 `json:"out"`
	KB  float64 `json:"kb"` // kB/s vom Server
}

type GameWatch struct {
	Running bool         `json:"running"`
	Flow    GameFlow     `json:"flow"`
	Samples []GameSample `json:"samples"`
	Median  float64      `json:"median"`
	Tick    int          `json:"tick"`   // nächstliegende übliche Rate
	Stable  float64      `json:"stable"` // Anteil Sekunden ohne Einbruch, %
	Drops   int          `json:"drops"`  // Sekunden mit weniger als der Hälfte
	Note    string       `json:"note,omitempty"`
	Started int64        `json:"started"`
	PingTun float64      `json:"ping_tunnel"` // ms, -1 = keine Antwort
	PingDir float64      `json:"ping_direct"`
	PingHow string       `json:"ping_how,omitempty"`
	PingAt  int64        `json:"ping_at,omitempty"`
	Stale   int          `json:"-"`
}

type Games struct {
	app  *App
	mu   sync.Mutex
	st   GameWatch
	stop chan struct{}
}

var commonTicks = []int{10, 15, 20, 30, 32, 60, 64, 120, 128}

func nearestTick(r float64) int {
	best, bd := 0, 1e9
	for _, t := range commonTicks {
		d := (r - float64(t)) / float64(t)
		if d < 0 {
			d = -d
		}
		if d < bd {
			best, bd = t, d
		}
	}
	if bd > 0.15 {
		return 0 // keine übliche Rate
	}
	return best
}

func summarizeGame(s []GameSample) (med float64, tick int, stable float64, drops int) {
	var v []float64
	for _, x := range s {
		if x.In > 0 {
			v = append(v, x.In)
		}
	}
	if len(v) == 0 {
		return 0, 0, 0, 0
	}
	med = round1(median(v))
	for _, x := range s {
		if x.In < med*0.5 {
			drops++
		}
	}
	stable = round1(float64(len(s)-drops) * 100 / float64(len(s)))
	return med, nearestTick(med), stable, drops
}

func (g *Games) State() GameWatch {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.st
	st.Samples = append([]GameSample(nil), g.st.Samples...)
	return st
}

func (g *Games) Stop() {
	g.mu.Lock()
	if g.stop != nil {
		close(g.stop)
		g.stop = nil
	}
	g.st.Running = false
	g.mu.Unlock()
	g.app.broadcast("game", g.State())
}

const gameWatchScript = `F='%s'; K='%s'
while :; do
  echo "T $(cut -d' ' -f1 /proc/uptime)"
  grep -F "$K" "$F" 2>/dev/null | head -1
  sleep 1
done
`

// Watch beobachtet eine Verbindung sekündlich (bis Stop oder 10 Minuten).
func (g *Games) Watch(f GameFlow) error {
	a := g.app
	if net.ParseIP(f.Client) == nil || net.ParseIP(f.Server) == nil || (f.Proto != "udp" && f.Proto != "tcp") {
		return errors.New(a.tr("Ungültige Verbindung", "Invalid connection"))
	}
	g.Stop()
	stop := make(chan struct{})
	g.mu.Lock()
	g.stop = stop
	g.st = GameWatch{Running: true, Flow: f, Started: time.Now().Unix(), PingTun: -2, PingDir: -2}
	g.mu.Unlock()
	needle := fmt.Sprintf("src=%s dst=%s sport=%d dport=%d ", f.Client, f.Server, f.CPort, f.SPort)
	go g.loop(needle, stop)
	return nil
}

func (g *Games) loop(needle string, stop chan struct{}) {
	a := g.app
	s, err := a.router.Session()
	if err != nil {
		g.finish(err.Error())
		return
	}
	defer s.Close()
	s.Stdin = strings.NewReader(fmt.Sprintf(gameWatchScript, shellQuote(conntrackPath), shellQuote(needle)))
	out, err := s.StdoutPipe()
	if err != nil || s.Start("sh -s") != nil {
		g.finish(a.tr("Messung konnte nicht starten", "Measurement could not start"))
		return
	}
	go func() {
		select {
		case <-stop:
		case <-time.After(10 * time.Minute):
		}
		s.Close()
	}()
	sc := bufio.NewScanner(out)
	var prevT, curT float64
	var prev ctEntry
	havePrev, haveCur := false, false
	var cur ctEntry
	missing := 0
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "T ") {
			if haveCur && havePrev && curT > prevT && cur.haveCounters {
				dt := curT - prevT
				sm := GameSample{T: time.Now().UnixMilli()}
				if cur.rpkts >= prev.rpkts {
					sm.In = round1(float64(cur.rpkts-prev.rpkts) / dt)
					sm.KB = round1(float64(cur.rbytes-prev.rbytes) / dt / 1000)
				}
				if cur.pkts >= prev.pkts {
					sm.Out = round1(float64(cur.pkts-prev.pkts) / dt)
				}
				g.mu.Lock()
				g.st.Samples = append(g.st.Samples, sm)
				if len(g.st.Samples) > 600 {
					g.st.Samples = g.st.Samples[len(g.st.Samples)-600:]
				}
				g.st.Median, g.st.Tick, g.st.Stable, g.st.Drops = summarizeGame(g.st.Samples)
				// zählt der Zähler nicht (Hardware-Beschleunigung), obwohl die Verbindung lebt?
				if sm.In == 0 && sm.Out == 0 {
					g.st.Stale++
				} else {
					g.st.Stale = 0
				}
				if g.st.Stale >= 5 {
					g.st.Note = a.tr("Seit 5 Sekunden zählt der Router keine Pakete dieser Verbindung – entweder ruht das Spiel (Menü, Ladebildschirm) oder die Hardware-Beschleunigung umgeht den Zähler.", "No packets counted for 5 seconds – the game may be idle (menu, loading) or hardware acceleration bypasses the counter.")
				} else {
					g.st.Note = ""
				}
				st := g.st
				st.Samples = nil
				g.mu.Unlock()
				a.broadcast("gamesample", map[string]any{"sample": sm, "state": st})
			}
			if haveCur {
				prev, prevT, havePrev = cur, curT, true
			} else {
				missing++
				if missing >= 15 {
					g.finish(a.tr("Die Verbindung ist beendet.", "The connection has ended."))
					return
				}
			}
			curT, _ = strconv.ParseFloat(strings.TrimSpace(l[2:]), 64)
			haveCur = false
			continue
		}
		if e, ok := parseConntrack(l); ok {
			cur, haveCur, missing = e, true, 0
		}
	}
	g.finish("")
}

func (g *Games) finish(note string) {
	g.mu.Lock()
	g.st.Running = false
	if note != "" {
		g.st.Note = note
	}
	if g.stop != nil {
		close(g.stop)
		g.stop = nil
	}
	g.mu.Unlock()
	g.app.broadcast("game", g.State())
}

const gamePingScript = `S='%s'; P='%s'; PR='%s'; T='%s'; W='%s'
m() {
  I="$1"
  if [ "$PR" = tcp ] && command -v curl >/dev/null 2>&1; then
    for n in 1 2 3 4 5; do curl -s -o /dev/null -m 3 --interface "$I" -w '%%{time_connect}\n' "http://$S:$P/" 2>/dev/null; done | awk -v i="$I" '$1>0{v=$1*1000; if(!c||v<mn)mn=v; c++} END{ if(c) printf "R %%s tcp %%.1f\n", i, mn; else printf "R %%s tcp -1\n", i }'
  else
    ping -c 5 -W 1 -I "$I" "$S" 2>/dev/null | awk -v i="$I" '/time=/{t=$0; sub(/.*time=/,"",t); sub(/[ ]*ms.*/,"",t); c++; s+=t} END{ if(c) printf "R %%s icmp %%.1f\n", i, s/c; else printf "R %%s icmp -1\n", i }'
  fi
}
[ -n "$T" ] && m "$T"
[ -n "$W" ] && m "$W"
echo DONE
`

// Ping misst den Spielserver durch den Tunnel und direkt über die Leitung.
func (g *Games) Ping() error {
	a := g.app
	g.mu.Lock()
	f := g.st.Flow
	g.mu.Unlock()
	if net.ParseIP(f.Server) == nil {
		return errors.New(a.tr("Keine Verbindung ausgewählt", "No connection selected"))
	}
	tn, ok := a.defaultTunnel()
	tIf := ""
	if ok && reIface.MatchString(tn.Iface) {
		tIf = tn.Iface
	}
	_, _, inf := a.router.State()
	wan := ""
	if reIface.MatchString(inf.WAN) {
		wan = inf.WAN
	}
	out, err := a.router.Run(fmt.Sprintf(gamePingScript, f.Server, strconv.Itoa(f.SPort), f.Proto, tIf, wan), 60*time.Second)
	if err != nil && !strings.Contains(out, "DONE") {
		return err
	}
	res := map[string]float64{}
	how := ""
	for _, l := range strings.Split(out, "\n") {
		x := strings.Fields(l)
		if len(x) == 4 && x[0] == "R" {
			v, _ := strconv.ParseFloat(x[3], 64)
			res[x[1]] = v
			how = x[2]
		}
	}
	g.mu.Lock()
	g.st.PingTun, g.st.PingDir = -1, -1
	if v, ok := res[tIf]; ok && tIf != "" {
		g.st.PingTun = v
	}
	if v, ok := res[wan]; ok && wan != "" {
		g.st.PingDir = v
	}
	g.st.PingHow, g.st.PingAt = how, time.Now().Unix()
	g.mu.Unlock()
	g.app.broadcast("game", g.State())
	return nil
}

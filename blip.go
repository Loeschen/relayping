package main

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kurzaussetzer: erkennt Unterbrechungen ab etwa 2 Sekunden und ordnet sie ein.
//
//   - Internet: Der Router pingt jede Sekunde 1.1.1.1, 9.9.9.9 und 8.8.8.8 über die Leitung (am Tunnel
//     vorbei). Fehlen bei beiden gleichzeitig mindestens zwei Antworten, war die Leitung weg.
//   - Tunnel: Der Router pingt jede Sekunde das Mullvad-Gateway 10.64.0.1 durch jeden Tunnel.
//     Fehlen dort Antworten, während die Leitung lief, hing nur der Tunnel.
//   - PC ↔ Router: Der PC pingt jede Sekunde den Router. Fehlen dort Antworten, lag es am
//     WLAN/Kabel zwischen PC und Router.
//
// Ausgewertet wird nach der Paketnummer (seq) des Routers, nicht nach Ankunftszeit am PC –
// so verfälscht ein kurzer Hänger zwischen PC und Router die Messung der Leitung nicht.
// Es wird nur gepingt, am Router wird nichts verändert.

const (
	blipMin     = 1.75 // Sekunden: ab hier zählt es (≈ 2 verlorene Pings)
	blipLong    = 25.0 // länger: das normale Ausfall-Protokoll übernimmt
	blipStep    = 0.25
	blipKeepSec = 600
)

// probeStream: eine Ping-Folge im Sekundentakt, ausgewertet nach seq.
type probeStream struct {
	base     float64 // geschätzte Zeit von seq 0 (Unix-Sekunden)
	haveBase bool
	started  bool
	lastSeq  int // höchste gesehene seq (ohne Überlauf)
	wrap     int
	rawLast  int
	lost     []float64 // Startzeiten verlorener Pings
	upTo     float64   // bis hierhin ist alles bekannt
}

// reply verarbeitet eine Antwort (seq wie von ping gemeldet, Ankunft am PC, Laufzeit in ms).
func (p *probeStream) reply(rawSeq int, arrival time.Time, rttMs float64) {
	// 16-Bit-Überlauf der seq bei BusyBox
	if p.haveBase && rawSeq+30000 < p.rawLast {
		p.wrap += 65536
	}
	p.rawLast = rawSeq
	seq := rawSeq + p.wrap
	at := float64(arrival.UnixNano())/1e9 - rttMs/1000
	est := at - float64(seq)
	if !p.started {
		p.started, p.haveBase = true, true
		p.base, p.lastSeq = est, seq
		p.upTo = p.base + float64(seq)
		return
	}
	if est < p.base {
		p.base = est // geringste Verzögerung = beste Schätzung
	}
	if seq <= p.lastSeq {
		return // verspätet oder doppelt
	}
	for q := p.lastSeq + 1; q < seq; q++ {
		p.lost = append(p.lost, p.base+float64(q))
	}
	p.lastSeq = seq
	p.upTo = p.base + float64(seq)
	p.prune()
}

// sent/lostLocal: für Messungen, die der PC selbst macht (Zeit ist genau bekannt).
func (p *probeStream) local(sent time.Time, ok bool) {
	t := float64(sent.UnixNano()) / 1e9
	p.haveBase = true
	if !ok {
		p.lost = append(p.lost, t)
	}
	p.upTo = t + 1
	p.prune()
}

func (p *probeStream) prune() {
	cut := p.upTo - blipKeepSec
	i := 0
	for i < len(p.lost) && p.lost[i] < cut {
		i++
	}
	if i > 0 {
		p.lost = append([]float64(nil), p.lost[i:]...)
	}
}

func (p *probeStream) down(x float64) bool {
	i := sort.SearchFloat64s(p.lost, x+1e-3)
	return i > 0 && x < p.lost[i-1]+1
}

type Blips struct {
	app      *App
	mu       sync.Mutex
	streams  map[string]*probeStream // w1, w2, t:<iface>
	lan      *probeStream
	lanOK    bool               // PC hat den Router mindestens einmal per Ping erreicht
	marks    map[string]float64 // je Art und Ziel: bis hierhin ausgewertet
	inLong   map[string]bool    // je Art und Ziel: gerade in einem langen Ausfall
	names    map[string]string  // iface -> Tunnelname
	lastTick time.Time
	lastNote time.Time
}

func newBlips(a *App) *Blips {
	return &Blips{app: a, streams: map[string]*probeStream{}, lan: &probeStream{}, marks: map[string]float64{}, inLong: map[string]bool{}}
}

const blipScript = `W='%s'
echo "PID $$"
p() { k=$1; shift; ( ping "$@" 2>&1 | while IFS= read -r l; do echo "$k $l"; done ) & }
if [ -n "$W" ]; then O="-I $W"; else O=""; fi
p w1 $O 1.1.1.1; p w2 $O 9.9.9.9; p w3 $O 8.8.8.8
%s
wait
`

func (b *Blips) Run() {
	go b.runLAN()
	go b.evalLoop()
	for !b.app.quitting() {
		ok, _, inf := b.app.router.State()
		if !ok || inf.Checked.IsZero() {
			time.Sleep(3 * time.Second)
			continue
		}
		b.session(inf)
		if b.app.quitting() {
			return
		}
		time.Sleep(5 * time.Second)
	}
}

func tunnelSet(inf RouterInfo) string {
	var s []string
	for _, t := range inf.Tunnels {
		if reIface.MatchString(t.Iface) {
			s = append(s, t.Iface)
		}
	}
	sort.Strings(s)
	return strings.Join(s, " ")
}

func (b *Blips) session(inf RouterInfo) {
	a := b.app
	wan := inf.WAN
	if !reIface.MatchString(wan) {
		wan = ""
	}
	var tl []string
	names := map[string]string{}
	for _, t := range inf.Tunnels {
		if reIface.MatchString(t.Iface) {
			tl = append(tl, fmt.Sprintf("p 't:%s' -I '%s' 10.64.0.1", t.Iface, t.Iface))
			n := t.Name
			if n == "" {
				n = t.Iface
			}
			names[t.Iface] = n
		}
	}
	set := tunnelSet(inf)
	s, err := a.router.Session()
	if err != nil {
		return
	}
	defer s.Close()
	s.Stdin = strings.NewReader(fmt.Sprintf(blipScript, wan, strings.Join(tl, "\n")))
	out, err := s.StdoutPipe()
	if err != nil || s.Start("sh -s") != nil {
		return
	}
	b.mu.Lock()
	b.streams = map[string]*probeStream{}
	b.names = names
	for k := range b.marks {
		if k != "kurz-lan" {
			delete(b.marks, k)
		}
	}
	b.mu.Unlock()
	pid := ""
	defer func() {
		if _, err := strconv.Atoi(pid); err == nil {
			go a.router.Run("kill "+pid+" 2>/dev/null", 5*time.Second)
		}
	}()
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	check := time.NewTicker(10 * time.Second)
	defer check.Stop()
	for {
		select {
		case <-a.quit:
			return
		case <-check.C:
			ok, _, cur := a.router.State()
			if !ok || tunnelSet(cur) != set || cur.WAN != inf.WAN {
				return // Tunnel geändert: neu aufsetzen
			}
		case l, ok := <-lines:
			if !ok {
				return
			}
			key, rest, found := strings.Cut(l, " ")
			if !found {
				continue
			}
			if key == "PID" {
				pid = strings.TrimSpace(rest)
				continue
			}
			if strings.Contains(rest, "DUP!") {
				continue
			}
			m := reReply.FindStringSubmatch(rest)
			if m == nil {
				continue
			}
			seq, _ := strconv.Atoi(m[1])
			ms, _ := strconv.ParseFloat(m[2], 64)
			now := time.Now()
			b.mu.Lock()
			st := b.streams[key]
			if st == nil {
				st = &probeStream{}
				b.streams[key] = st
			}
			st.reply(seq, now, ms)
			b.mu.Unlock()
		}
	}
}

// runLAN: Der PC pingt jede Sekunde den Router (WLAN/Kabel zwischen PC und Router).
func (b *Blips) runLAN() {
	var ip net.IP
	for !b.app.quitting() {
		host := b.app.store.Get().RouterHost
		if ip == nil || ip.String() != host {
			ip = net.ParseIP(host)
			if ip == nil {
				if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
					ip = ips[0]
				}
			}
		}
		if ip == nil || ip.To4() == nil {
			time.Sleep(10 * time.Second)
			continue
		}
		start := time.Now()
		_, ok := pingHost(ip, 1500*time.Millisecond) // großzügig: WLAN-Stromsparen verzögert einzelne Antworten
		b.mu.Lock()
		if ok {
			b.lanOK = true
		}
		if b.lanOK {
			b.lan.local(start, ok)
		}
		b.mu.Unlock()
		if d := time.Second - time.Since(start); d > 0 {
			time.Sleep(d)
		}
	}
}

type blipRun struct {
	kind, target string
	start, end   float64
}

func (b *Blips) evalLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.app.quit:
			return
		case now := <-t.C:
			b.mu.Lock()
			// Ruhezustand des PCs: alte Daten verwerfen
			if !b.lastTick.IsZero() && now.Sub(b.lastTick) > 10*time.Second {
				b.streams = map[string]*probeStream{}
				b.lan = &probeStream{}
				b.marks = map[string]float64{}
				b.inLong = map[string]bool{}
			}
			b.lastTick = now
			runs := b.evaluate()
			b.mu.Unlock()
			for _, r := range runs {
				b.record(r)
			}
		}
	}
}

type blipCond struct {
	kind, target string
	f            func(float64) bool
	upTo         float64
}

// evaluate prüft je Art den Zeitraum, für den alle nötigen Folgen vollständig sind. Muss mit b.mu gerufen werden.
func (b *Blips) evaluate() []blipRun {
	var conds []blipCond
	// Internet gilt nur als weg, wenn alle unabhängigen Ziele (Cloudflare, Quad9, Google)
	// gleichzeitig fehlen – ein einzelner Anbieter, der kurz Pings verwirft, zählt nicht.
	var wan []*probeStream
	for _, k := range []string{"w1", "w2", "w3"} {
		if s := b.streams[k]; s != nil && s.started {
			wan = append(wan, s)
		}
	}
	if len(wan) >= 2 {
		wanUpTo := wan[0].upTo
		for _, s := range wan[1:] {
			wanUpTo = math.Min(wanUpTo, s.upTo)
		}
		wanDown := func(x float64) bool {
			for _, s := range wan {
				if !s.down(x) {
					return false
				}
			}
			return true
		}
		conds = append(conds, blipCond{"kurz-internet", "Internet", wanDown, wanUpTo})
		var tun []string
		for k, s := range b.streams {
			if strings.HasPrefix(k, "t:") && s.started {
				tun = append(tun, k)
			}
		}
		sort.Strings(tun)
		for _, k := range tun {
			s := b.streams[k]
			conds = append(conds, blipCond{"kurz-tunnel", strings.TrimPrefix(k, "t:"),
				func(x float64) bool { return s.down(x) && !wanDown(x) }, math.Min(wanUpTo, s.upTo)})
		}
	}
	if b.lanOK && b.lan.haveBase {
		conds = append(conds, blipCond{"kurz-lan", "PC ↔ Router", b.lan.down, b.lan.upTo})
	}
	var out []blipRun
	for _, c := range conds {
		key := c.kind + "|" + c.target
		from, ok := b.marks[key]
		if !ok {
			b.marks[key] = c.upTo // erst ab jetzt auswerten
			continue
		}
		next, runs, long := scanRuns(from, c, b.inLong[key])
		b.marks[key], b.inLong[key] = next, long
		out = append(out, runs...)
	}
	return out
}

// scanRuns sucht zusammenhängende Ausfälle zwischen from und c.upTo. Läuft ein Ausfall bis
// zum Ende des bekannten Zeitraums, wird er beim nächsten Mal weiter betrachtet.
func scanRuns(from float64, c blipCond, inLong bool) (float64, []blipRun, bool) {
	if c.upTo <= from {
		return from, nil, inLong
	}
	var out []blipRun
	start := -1.0
	x := from
	for ; x < c.upTo; x += blipStep {
		d := c.f(x)
		if inLong { // Rest eines langen Ausfalls überspringen
			if !d {
				inLong = false
			}
			continue
		}
		if d && start < 0 {
			start = x
		}
		if !d && start >= 0 {
			if x-start >= blipMin && x-start < blipLong {
				out = append(out, blipRun{c.kind, c.target, start, x})
			}
			start = -1
		}
	}
	if start >= 0 {
		if c.upTo-start < blipLong {
			return start, out, false // noch offen
		}
		return x, out, true
	}
	return x, out, inLong
}

func (b *Blips) record(r blipRun) {
	a := b.app
	dur := int64(math.Round(r.end - r.start))
	if dur < 2 {
		dur = 2
	}
	start := int64(math.Round(r.start))
	if r.kind == "kurz-tunnel" { // Tunnelname aus dem aktuellen Stand (beim Start evtl. noch unbekannt)
		_, _, inf := a.router.State()
		for _, t := range inf.Tunnels {
			if t.Iface == r.target && t.Name != "" {
				r.target = t.Name
			}
		}
	}
	if merged := a.outages.AddBlip(r.kind, r.target, start, start+dur); merged {
		a.log.Printf("Kurzaussetzer (zusammengefasst): %s %s %d s", r.kind, r.target, dur)
		return
	}
	var msg string
	switch r.kind {
	case "kurz-internet":
		msg = fmt.Sprintf(a.tr("Internet war %d s weg (%s)", "Internet was gone for %d s (%s)"), dur, time.Unix(start, 0).Format("15:04:05"))
	case "kurz-tunnel":
		msg = fmt.Sprintf(a.tr("Tunnel „%s“ war %d s weg, die Leitung lief (%s)", "Tunnel “%s” was gone for %d s while the line was fine (%s)"), r.target, dur, time.Unix(start, 0).Format("15:04:05"))
	default:
		msg = fmt.Sprintf(a.tr("Verbindung PC ↔ Router war %d s weg – WLAN/Kabel (%s)", "PC ↔ router connection was gone for %d s – Wi-Fi/cable (%s)"), dur, time.Unix(start, 0).Format("15:04:05"))
	}
	a.day.Event("ausfall", msg)
	a.push("kurz", a.tr("Kurzaussetzer", "Short dropout"), msg)
	b.mu.Lock()
	quiet := time.Since(b.lastNote) < 5*time.Minute
	if !quiet {
		b.lastNote = time.Now()
	}
	b.mu.Unlock()
	if quiet {
		a.log.Printf("Kurzaussetzer: %s", msg)
	} else {
		a.notify(a.tr("RelayPing: Kurzaussetzer", "RelayPing: short dropout"), msg)
	}
}

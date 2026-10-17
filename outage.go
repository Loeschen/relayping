package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Ausfall-Protokoll: alle 10 Sekunden prüft der Router das Internet (Ping an
// 1.1.1.1 / 9.9.9.9 über die Leitung) und jeden Tunnel (Ping an das
// Mullvad-Gateway 10.64.0.1 durch den Tunnel). Drei Fehlschläge in Folge
// gelten als Ausfall. Zusätzlich werden Router-Neustarts erkannt.

type Outage struct {
	ID     int64  `json:"id"`
	Kind   string `json:"kind"` // internet, tunnel, router, neustart
	Target string `json:"target"`
	Start  int64  `json:"start"`
	End    int64  `json:"end"` // 0 = läuft noch
	Note   string `json:"note,omitempty"`
	Count  int    `json:"count,omitempty"` // Kurzaussetzer: so viele, dicht hintereinander zusammengefasst
	Lost   int64  `json:"lost,omitempty"`  // Kurzaussetzer: Sekunden ohne Verbindung (Summe)
}

type outageFile struct {
	List      []Outage `json:"ausfaelle"`
	Boot      int64    `json:"boot"`
	Next      int64    `json:"next"`
	FritzConn int64    `json:"fritzbox_verbindung,omitempty"` // Beginn der aktuellen Internetverbindung der FRITZ!Box
	FritzBoot int64    `json:"fritzbox_start,omitempty"`
}

type Outages struct {
	app      *App
	mu       sync.Mutex
	file     string
	d        outageFile
	fails    map[string]int   // Ziel -> Fehlschläge in Folge
	first    map[string]int64 // Ziel -> Zeit des ersten Fehlschlags
	open     map[string]int64 // Ziel -> ID des offenen Ausfalls
	lostAt   int64
	lastTick int64
	fritzEnd int64 // Ende des letzten FRITZ!Box-Ausfalls (danach ist eine Neuverbindung normal)
}

const outageThreshold = 3

func newOutages(a *App, file string) *Outages {
	o := &Outages{app: a, file: file, fails: map[string]int{}, first: map[string]int64{}, open: map[string]int64{}}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &o.d)
	}
	o.d.List = mergeBlips(o.d.List)
	// Ausfälle, die beim letzten Beenden noch offen waren, gelten als beendet (Ende unbekannt)
	for i := range o.d.List {
		if o.d.List[i].End == 0 {
			o.d.List[i].End = o.d.List[i].Start
			o.d.List[i].Note = "Ende unbekannt (RelayPing wurde beendet)"
		}
	}
	return o
}

func (o *Outages) saveLocked() {
	cut := time.Now().AddDate(0, 0, -90).Unix()
	var keep []Outage
	for _, x := range o.d.List {
		if x.Start >= cut {
			keep = append(keep, x)
		}
	}
	o.d.List = keep
	if b, err := json.MarshalIndent(o.d, "", "  "); err == nil {
		writeAtomic(o.file, b)
	}
}

func (o *Outages) openLocked(key, kind, target string, start int64, note string) {
	if _, ok := o.open[key]; ok {
		return
	}
	o.d.Next++
	o.d.List = append(o.d.List, Outage{ID: o.d.Next, Kind: kind, Target: target, Start: start, Note: note})
	o.open[key] = o.d.Next
}

func (o *Outages) closeLocked(key string, end int64) *Outage {
	id, ok := o.open[key]
	if !ok {
		return nil
	}
	delete(o.open, key)
	for i := range o.d.List {
		if o.d.List[i].ID == id {
			o.d.List[i].End = end
			x := o.d.List[i]
			return &x
		}
	}
	return nil
}

// check verarbeitet ein Prüfergebnis für ein Ziel.
func (o *Outages) checkLocked(key, kind, target string, ok bool, now int64) (opened, closed *Outage) {
	if ok {
		o.fails[key] = 0
		if c := o.closeLocked(key, now); c != nil {
			return nil, c
		}
		return nil, nil
	}
	if o.fails[key] == 0 {
		o.first[key] = now
	}
	o.fails[key]++
	if o.fails[key] == outageThreshold {
		o.openLocked(key, kind, target, o.first[key], "")
		x := o.d.List[len(o.d.List)-1]
		return &x, nil
	}
	return nil, nil
}

// Observe wird nach jeder Router-Abfrage aufgerufen.
func (o *Outages) Observe(connected bool, inf RouterInfo, now time.Time) {
	a := o.app
	n := now.Unix()
	var events []string
	o.mu.Lock()
	// Lange Pause (PC im Ruhezustand): nicht als Ausfall werten
	if o.lastTick != 0 && n-o.lastTick > 40 {
		o.lostAt = 0
		for k := range o.fails {
			o.fails[k] = 0
		}
	}
	o.lastTick = n
	// Router für RelayPing nicht erreichbar
	if !connected {
		if o.lostAt == 0 {
			o.lostAt = n
		} else if n-o.lostAt >= 30 {
			o.openLocked("router", "router", "", o.lostAt, "")
		}
		o.mu.Unlock()
		return
	}
	if o.lostAt != 0 {
		if c := o.closeLocked("router", n); c != nil {
			events = append(events, fmt.Sprintf(a.tr("Router war %s nicht erreichbar", "Router was unreachable for %s"), durText(a, c.End-c.Start)))
		}
		o.lostAt = 0
	}
	// Router-Neustart
	if inf.BootTime > 0 {
		if o.d.Boot != 0 && inf.BootTime > o.d.Boot+60 {
			o.d.Next++
			o.d.List = append(o.d.List, Outage{ID: o.d.Next, Kind: "neustart", Start: inf.BootTime, End: inf.BootTime})
			events = append(events, a.tr("Router wurde neu gestartet", "Router was restarted"))
		}
		o.d.Boot = inf.BootTime
	}
	if inf.WANOK >= 0 {
		op, cl := o.checkLocked("internet", "internet", inf.WAN, inf.WANOK == 1, n)
		if op != nil {
			events = append(events, a.tr("Internet-Ausfall erkannt", "Internet outage detected"))
		}
		if cl != nil {
			events = append(events, fmt.Sprintf(a.tr("Internet wieder da (Ausfall %s)", "Internet back (outage %s)"), durText(a, cl.End-cl.Start)))
		}
	}
	internetDown := o.open["internet"] != 0
	for _, t := range inf.Tunnels {
		if t.Probe < 0 || internetDown {
			continue
		}
		name := t.Name
		if name == "" {
			name = t.Iface
		}
		target := name + " (" + t.Host + ")"
		op, cl := o.checkLocked("tunnel:"+t.Iface, "tunnel", target, t.Probe == 1, n)
		if op != nil {
			events = append(events, fmt.Sprintf(a.tr("Tunnel %s antwortet nicht", "Tunnel %s not responding"), target))
		}
		if cl != nil {
			events = append(events, fmt.Sprintf(a.tr("Tunnel %s wieder da (Ausfall %s)", "Tunnel %s back (outage %s)"), target, durText(a, cl.End-cl.Start)))
		}
	}
	changed := len(events) > 0
	if changed {
		o.saveLocked()
	}
	o.mu.Unlock()
	for _, e := range events {
		a.notify(a.tr("RelayPing: Verbindung", "RelayPing: connection"), e)
		a.push("ausfall", a.tr("Verbindung", "Connection"), e)
		a.day.Event("ausfall", e)
	}
	if changed {
		a.broadcast("outages", o.List())
		o.writeCSV()
	}
}

// ObserveFritz wertet den Zustand der FRITZ!Box aus: Internetverbindung weg,
// Neuverbindung (neue IP, z. B. Zwangstrennung) und Neustart der Box.
func (o *Outages) ObserveFritz(st FritzStatus, now time.Time) {
	if !st.OK {
		return
	}
	a := o.app
	n := now.Unix()
	var events []string
	o.mu.Lock()
	b0, c0 := o.d.FritzBoot, o.d.FritzConn
	rebooted := false
	if st.BootTime > 0 {
		if o.d.FritzBoot != 0 && st.BootTime > o.d.FritzBoot+90 {
			o.d.Next++
			o.d.List = append(o.d.List, Outage{ID: o.d.Next, Kind: "fritz-neustart", Target: "FRITZ!Box", Start: st.BootTime, End: st.BootTime})
			events = append(events, a.tr("FRITZ!Box wurde neu gestartet", "FRITZ!Box was restarted"))
			rebooted = true
		}
		if o.d.FritzBoot == 0 || st.BootTime > o.d.FritzBoot+90 {
			o.d.FritzBoot = st.BootTime
		}
	}
	if st.Conn != "" {
		op, cl := o.checkLocked("fritz", "fritz", "FRITZ!Box", st.Conn == "Connected", n)
		if op != nil {
			events = append(events, a.tr("FRITZ!Box hat keine Internetverbindung", "FRITZ!Box has no internet connection"))
		}
		if cl != nil {
			events = append(events, fmt.Sprintf(a.tr("FRITZ!Box wieder online (Ausfall %s)", "FRITZ!Box back online (outage %s)"), durText(a, cl.End-cl.Start)))
			o.fritzEnd = n
		}
	}
	if st.ConnSince > 0 {
		if o.d.FritzConn != 0 && st.ConnSince > o.d.FritzConn+90 && !rebooted && o.open["fritz"] == 0 && n-o.fritzEnd > 300 {
			o.d.Next++
			o.d.List = append(o.d.List, Outage{ID: o.d.Next, Kind: "fritz-neu", Target: "FRITZ!Box", Start: st.ConnSince, End: st.ConnSince})
			events = append(events, a.tr("FRITZ!Box hat die Internetverbindung neu aufgebaut", "FRITZ!Box re-established the internet connection"))
		}
		if o.d.FritzConn == 0 || st.ConnSince > o.d.FritzConn+90 {
			o.d.FritzConn = st.ConnSince
		}
	}
	if len(events) > 0 || b0 != o.d.FritzBoot || c0 != o.d.FritzConn {
		o.saveLocked()
	}
	o.mu.Unlock()
	for _, e := range events {
		a.notify(a.tr("RelayPing: FRITZ!Box", "RelayPing: FRITZ!Box"), e)
		a.push("ausfall", "FRITZ!Box", e)
		a.day.Event("ausfall", e)
	}
	if len(events) > 0 {
		a.broadcast("outages", o.List())
		o.writeCSV()
	}
}

// AddBlip trägt einen Kurzaussetzer ein (kurz-internet, kurz-tunnel, kurz-lan).
// Liegen Kurzaussetzer derselben Art höchstens 60 s auseinander, werden sie zu einer
// „unruhigen Phase“ zusammengefasst (merged = true).
func (o *Outages) AddBlip(kind, target string, start, end int64) (merged bool) {
	o.mu.Lock()
	for i := len(o.d.List) - 1; i >= 0 && i >= len(o.d.List)-20; i-- {
		x := &o.d.List[i]
		if x.Kind == kind && x.Target == target && start-x.End <= 60 && start >= x.Start {
			if x.Count == 0 {
				x.Count, x.Lost = 1, x.End-x.Start
			}
			x.Count++
			x.Lost += end - start
			if end > x.End {
				x.End = end
			}
			merged = true
			break
		}
	}
	if !merged {
		o.d.Next++
		o.d.List = append(o.d.List, Outage{ID: o.d.Next, Kind: kind, Target: target, Start: start, End: end})
	}
	o.saveLocked()
	o.mu.Unlock()
	o.app.broadcast("outages", o.List())
	o.writeCSV()
	return merged
}

// mergeBlips fasst ältere, einzeln gespeicherte Kurzaussetzer-Serien nachträglich zusammen.
func mergeBlips(l []Outage) []Outage {
	sort.SliceStable(l, func(i, j int) bool { return l[i].Start < l[j].Start })
	var out []Outage
	last := map[string]int{} // Art|Ziel -> Index in out
	for _, x := range l {
		if !x.isBlip() {
			out = append(out, x)
			continue
		}
		k := x.Kind + "|" + x.Target
		if i, ok := last[k]; ok && x.Start-out[i].End <= 60 {
			p := &out[i]
			if p.Count == 0 {
				p.Count, p.Lost = 1, p.End-p.Start
			}
			n := max(1, x.Count)
			lost := x.Lost
			if lost == 0 {
				lost = x.End - x.Start
			}
			p.Count += n
			p.Lost += lost
			if x.End > p.End {
				p.End = x.End
			}
			continue
		}
		out = append(out, x)
		last[k] = len(out) - 1
	}
	return out
}

func (x Outage) isBlip() bool { return strings.HasPrefix(x.Kind, "kurz-") }

// isEvent: Einträge ohne Dauer (Neustarts, Neuverbindungen) zählen nicht als Ausfall.
func (x Outage) isEvent() bool {
	return x.Kind == "neustart" || x.Kind == "fritz-neustart" || x.Kind == "fritz-neu"
}

func durText(a *App, s int64) string {
	switch {
	case s < 90:
		return fmt.Sprintf("%d s", s)
	case s < 5400:
		return fmt.Sprintf("%d min", (s+30)/60)
	default:
		return fmt.Sprintf(a.tr("%.1f h", "%.1f h"), float64(s)/3600)
	}
}

func (o *Outages) List() []Outage {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := append([]Outage(nil), o.d.List...)
	sort.Slice(out, func(i, j int) bool { return out[i].Start > out[j].Start })
	return out
}

func (o *Outages) writeCSV() {
	list := o.List()
	var b strings.Builder
	b.WriteString("\xef\xbb\xbfBeginn;Ende;Dauer s;Art;Betroffen;Hinweis\r\n")
	for i := len(list) - 1; i >= 0; i-- {
		x := list[i]
		end, dur := "", ""
		if x.End > 0 {
			end = time.Unix(x.End, 0).Format("02.01.2006 15:04:05")
			dur = fmt.Sprint(x.End - x.Start)
		}
		fmt.Fprintf(&b, "%s;%s;%s;%s;%s;%s\r\n", time.Unix(x.Start, 0).Format("02.01.2006 15:04:05"), end, dur, x.Kind,
			strings.ReplaceAll(x.Target, ";", ","), strings.ReplaceAll(x.Note, ";", ","))
	}
	dir := o.app.store.File("verlauf")
	_ = os.MkdirAll(dir, 0o755)
	writeAtomic(filepath.Join(dir, "ausfaelle.csv"), []byte(b.String()))
}

func (a *App) outageText(o Outage) string {
	dur := a.tr("läuft noch", "ongoing")
	if o.End > 0 {
		dur = durText(a, o.End-o.Start)
	}
	switch o.Kind {
	case "internet":
		return fmt.Sprintf(a.tr("Internet ausgefallen (%s)", "Internet down (%s)"), dur)
	case "tunnel":
		return fmt.Sprintf(a.tr("Tunnel %s ohne Verbindung (%s)", "Tunnel %s without connection (%s)"), o.Target, dur)
	case "router":
		return fmt.Sprintf(a.tr("Router für RelayPing nicht erreichbar (%s)", "Router unreachable for RelayPing (%s)"), dur)
	case "neustart":
		return a.tr("Router neu gestartet", "Router restarted")
	case "kurz-internet", "kurz-tunnel", "kurz-lan", "kurz-dns":
		what := map[string][2]string{"kurz-internet": {"Internet", "internet"}, "kurz-tunnel": {"Tunnel " + o.Target, "tunnel " + o.Target},
			"kurz-lan": {"PC ↔ Router (WLAN/Kabel)", "PC ↔ router (Wi-Fi/cable)"}, "kurz-dns": {"DNS (" + o.Target + ")", "DNS (" + o.Target + ")"}}[o.Kind]
		if o.Count > 1 {
			return fmt.Sprintf(a.tr("%s unruhig: %d Aussetzer in %s, zusammen %s weg", "%s unstable: %d dropouts within %s, %s gone in total"),
				a.tr(what[0], what[1]), o.Count, durText(a, o.End-o.Start), durText(a, o.Lost))
		}
		return fmt.Sprintf(a.tr("Kurzaussetzer %s (%s)", "Short dropout %s (%s)"), a.tr(what[0], what[1]), dur)
	case "fritz":
		return fmt.Sprintf(a.tr("FRITZ!Box ohne Internetverbindung (%s)", "FRITZ!Box without internet connection (%s)"), dur)
	case "fritz-neu":
		return a.tr("FRITZ!Box hat die Internetverbindung neu aufgebaut", "FRITZ!Box re-established the internet connection")
	case "fritz-neustart":
		return a.tr("FRITZ!Box neu gestartet", "FRITZ!Box restarted")
	}
	return o.Kind
}

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tagesbericht: RelayPing merkt sich 24 Stunden lang die Minutenwerte der
// beobachteten Server, welche Server die Tunnel genutzt haben, Wechsel und
// Warnungen. Alle 5 Minuten schreibt es daraus relayping-bericht.txt und
// relayping-bericht.json – die Grundlage für die tägliche Mail.

const dayKeep = 24 * time.Hour

type MinStat struct {
	T    int64   `json:"t"` // Unix-Sekunden (Minutenbeginn)
	Sent int     `json:"s"`
	Recv int     `json:"r"`
	Sum  float64 `json:"sum"`
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	JSum float64 `json:"js"`
	JN   int     `json:"jn"`
}

type Segment struct {
	Iface string `json:"iface"`
	Name  string `json:"name"`
	Host  string `json:"host"`
	From  int64  `json:"from"`
	To    int64  `json:"to"`
}

type DayEvent struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"` // wechsel, warnung
	Text string `json:"text"`
}

type dayFile struct {
	Mins   map[string][]MinStat `json:"minuten"`
	Segs   []Segment            `json:"tunnel"`
	Events []DayEvent           `json:"ereignisse"`
}

type Day struct {
	app  *App
	mu   sync.Mutex
	file string
	d    dayFile
}

func newDay(a *App, file string) *Day {
	d := &Day{app: a, file: file, d: dayFile{Mins: map[string][]MinStat{}}}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &d.d)
	}
	if d.d.Mins == nil {
		d.d.Mins = map[string][]MinStat{}
	}
	d.mu.Lock()
	d.pruneLocked(time.Now())
	d.mu.Unlock()
	return d
}

func (d *Day) pruneLocked(now time.Time) {
	cut := now.Add(-dayKeep - time.Hour).Unix()
	for h, v := range d.d.Mins {
		i := 0
		for i < len(v) && v[i].T < cut {
			i++
		}
		if i == len(v) {
			delete(d.d.Mins, h)
		} else {
			d.d.Mins[h] = append([]MinStat(nil), v[i:]...)
		}
	}
	var segs []Segment
	for _, s := range d.d.Segs {
		if s.To >= cut {
			segs = append(segs, s)
		}
	}
	d.d.Segs = segs
	var ev []DayEvent
	for _, e := range d.d.Events {
		if e.T >= cut {
			ev = append(ev, e)
		}
	}
	d.d.Events = ev
}

// AddMinute übernimmt einen abgeschlossenen Minutenwert eines Monitors.
func (d *Day) AddMinute(host string, b minuteBucket) {
	if d == nil || b.sent == 0 {
		return
	}
	m := MinStat{T: b.start.Unix(), Sent: b.sent, Recv: b.recv, Sum: b.sum, Min: b.mn, Max: b.mx, JSum: b.jsum, JN: b.jn}
	d.mu.Lock()
	d.d.Mins[host] = append(d.d.Mins[host], m)
	d.mu.Unlock()
}

// Tunnels hält fest, welcher Server zu welcher Zeit in welchem Tunnel aktiv war.
func (d *Day) Tunnels(ts []Tunnel, now time.Time) {
	if d == nil {
		return
	}
	n := now.Unix()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range ts {
		if t.Host == "" {
			continue
		}
		found := false
		for i := len(d.d.Segs) - 1; i >= 0; i-- {
			s := &d.d.Segs[i]
			if s.Iface != t.Iface {
				continue
			}
			// gleicher Server und Lücke unter 5 Minuten: Abschnitt verlängern
			if s.Host == t.Host && n-s.To < 300 {
				s.To = n
				if t.Name != "" {
					s.Name = t.Name
				}
				found = true
			}
			break
		}
		if !found {
			d.d.Segs = append(d.d.Segs, Segment{Iface: t.Iface, Name: t.Name, Host: t.Host, From: n, To: n})
		}
	}
}

func (d *Day) Event(kind, text string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.d.Events = append(d.d.Events, DayEvent{T: time.Now().Unix(), Kind: kind, Text: text})
	d.mu.Unlock()
}

func (d *Day) save() {
	d.mu.Lock()
	d.pruneLocked(time.Now())
	b, err := json.Marshal(d.d)
	d.mu.Unlock()
	if err != nil {
		return
	}
	tmp := d.file + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, d.file)
	}
}

// Run speichert und schreibt den Bericht alle 5 Minuten (und kurz nach dem Start).
func (d *Day) Run() {
	time.Sleep(2 * time.Minute)
	for !d.app.quitting() {
		d.save()
		d.writeReport()
		select {
		case <-d.app.quit:
		case <-time.After(5 * time.Minute):
		}
	}
	d.save()
}

// ---------- Auswertung ----------

type QStats struct {
	Minutes int     `json:"minuten"`
	Avg     float64 `json:"ping_ms"`
	P95     float64 `json:"ping_p95_ms"`
	Min     float64 `json:"ping_min_ms"`
	Max     float64 `json:"ping_max_ms"`
	Jitter  float64 `json:"jitter_ms"`
	Loss    float64 `json:"verlust_prozent"`
	BadMins int     `json:"minuten_mit_verlust"`
}

func summarize(mins []MinStat) QStats {
	var q QStats
	var sent, recv, jn int
	var sum, js float64
	var avgs []float64
	for _, m := range mins {
		q.Minutes++
		sent += m.Sent
		recv += m.Recv
		sum += m.Sum
		js += m.JSum
		jn += m.JN
		if m.Recv < m.Sent {
			q.BadMins++
		}
		if m.Recv > 0 {
			avgs = append(avgs, m.Sum/float64(m.Recv))
			if q.Min == 0 || m.Min < q.Min {
				q.Min = m.Min
			}
			if m.Max > q.Max {
				q.Max = m.Max
			}
		}
	}
	if recv > 0 {
		q.Avg = round1(sum / float64(recv))
	}
	if jn > 0 {
		q.Jitter = round1(js / float64(jn))
	}
	if sent > 0 {
		q.Loss = math.Round(float64(sent-recv)*1000/float64(sent)) / 10
	}
	if len(avgs) > 0 {
		sort.Float64s(avgs)
		q.P95 = round1(avgs[int(math.Ceil(0.95*float64(len(avgs))))-1])
	}
	q.Min, q.Max = round1(q.Min), round1(q.Max)
	return q
}

// grade bewertet die Verbindung: 4 sehr gut … 1 schlecht.
func grade(q QStats, best float64) int {
	if q.Minutes == 0 {
		return 0
	}
	g := 4
	if q.Loss >= 0.5 || q.Jitter >= 3 || (best > 0 && q.Avg > best+5) {
		g = 3
	}
	if q.Loss >= 2 || q.Jitter >= 8 || (best > 0 && q.Avg > best*1.5+5) {
		g = 2
	}
	if q.Loss >= 5 || q.Jitter >= 20 {
		g = 1
	}
	return g
}

type TunnelReport struct {
	Name       string    `json:"name"`
	Iface      string    `json:"iface"`
	Host       string    `json:"server"`
	City       string    `json:"stadt"`
	Country    string    `json:"land"`
	Since      int64     `json:"seit"`
	Handshake  int64     `json:"handshake_vor_s"`
	HSWarn     bool      `json:"handshake_problem"`
	Now        QStats    `json:"aktueller_server_24h"`
	Day        QStats    `json:"tunnel_24h"`
	Grade      int       `json:"bewertung"`
	GradeText  string    `json:"bewertung_text"`
	BestHost   string    `json:"bester_server"`
	BestMedian float64   `json:"bester_median_ms"`
	SpeedMbps  float64   `json:"speedtest_mbit"`
	SpeedAt    int64     `json:"speedtest_zeit,omitempty"`
	Servers    []string  `json:"server_heute"`
	Segments   []Segment `json:"abschnitte"`
}

type Report struct {
	Generated int64          `json:"erstellt"`
	Version   string         `json:"version"`
	Tunnels   []TunnelReport `json:"tunnel"`
	Events    []DayEvent     `json:"ereignisse"`
	Router    map[string]any `json:"router"`
	Connected bool           `json:"router_verbunden"`
	Text      string         `json:"text"`
}

func (a *App) gradeText(g int) string {
	switch g {
	case 4:
		return a.tr("sehr gut", "very good")
	case 3:
		return a.tr("gut", "good")
	case 2:
		return a.tr("mäßig", "fair")
	case 1:
		return a.tr("schlecht", "poor")
	}
	return a.tr("keine Messwerte", "no data")
}

// Build erzeugt den Bericht über die letzten 24 Stunden.
func (d *Day) Build(now time.Time) Report {
	a := d.app
	ok, _, inf := a.router.State()
	rep := Report{Generated: now.Unix(), Version: version, Connected: ok}
	cut := now.Add(-dayKeep).Unix()

	d.mu.Lock()
	mins := map[string][]MinStat{}
	for h, v := range d.d.Mins {
		mins[h] = append([]MinStat(nil), v...)
	}
	segs := append([]Segment(nil), d.d.Segs...)
	for _, e := range d.d.Events {
		if e.T >= cut {
			rep.Events = append(rep.Events, e)
		}
	}
	d.mu.Unlock()

	speed := a.speed.State()
	for _, t := range inf.Tunnels {
		if t.Host == "" {
			continue
		}
		tr := TunnelReport{Name: t.Name, Iface: t.Iface, Host: t.Host, City: t.City, Country: regionDE(t.CC, a), Handshake: t.HSAge,
			HSWarn: (t.HSAge > 180 || t.HSAge < 0) && t.TXRate > 1000}
		if tr.Name == "" {
			tr.Name = t.Iface
		}
		// Abschnitte dieses Tunnels in den letzten 24 h
		var mine []Segment
		seen := map[string]bool{}
		for _, s := range segs {
			if s.Iface == t.Iface && s.To >= cut {
				if s.From < cut {
					s.From = cut
				}
				mine = append(mine, s)
				if !seen[s.Host] {
					seen[s.Host] = true
					tr.Servers = append(tr.Servers, s.Host)
				}
			}
		}
		tr.Segments = mine
		if len(mine) > 0 && mine[len(mine)-1].Host == t.Host {
			tr.Since = mine[len(mine)-1].From
		}
		// Minutenwerte: aktueller Server (24 h) und Tunnel (nur Zeiten, in denen der Server aktiv war)
		var cur []MinStat
		for _, m := range mins[t.Host] {
			if m.T >= cut {
				cur = append(cur, m)
			}
		}
		tr.Now = summarize(cur)
		var tun []MinStat
		for _, s := range mine {
			for _, m := range mins[s.Host] {
				if m.T >= s.From-60 && m.T <= s.To {
					tun = append(tun, m)
				}
			}
		}
		if len(tun) == 0 {
			tun = cur
		}
		tr.Day = summarize(tun)
		if b, ok := a.board.Best(t.CC); ok {
			tr.BestHost, tr.BestMedian = b.Host, b.Median
		} else if s, ok := a.scanner.Best(t.CC); ok {
			tr.BestHost, tr.BestMedian = s.Host, round1(s.Avg)
		}
		tr.Grade = grade(tr.Day, tr.BestMedian)
		tr.GradeText = a.gradeText(tr.Grade)
		if r, ok := speed.Results[t.Host]; ok && now.Sub(r.T) < 7*24*time.Hour {
			tr.SpeedMbps, tr.SpeedAt = r.Mbps, r.T.Unix()
		}
		rep.Tunnels = append(rep.Tunnels, tr)
	}
	sort.Slice(rep.Tunnels, func(i, j int) bool { return rep.Tunnels[i].Iface < rep.Tunnels[j].Iface })
	if ok {
		rep.Router = map[string]any{"modell": inf.Model, "wan": inf.WAN, "laufzeit_s": int64(inf.UptimeS), "temperatur_c": inf.TempC}
	}
	rep.Text = a.reportText(rep, now)
	return rep
}

func regionDE(cc string, a *App) string {
	de := map[string][2]string{"de": {"Deutschland", "Germany"}, "se": {"Schweden", "Sweden"}, "nl": {"Niederlande", "Netherlands"},
		"ch": {"Schweiz", "Switzerland"}, "at": {"Österreich", "Austria"}, "dk": {"Dänemark", "Denmark"}, "no": {"Norwegen", "Norway"},
		"fi": {"Finnland", "Finland"}, "fr": {"Frankreich", "France"}, "gb": {"Großbritannien", "United Kingdom"}, "us": {"USA", "USA"}}
	if v, ok := de[cc]; ok {
		return a.tr(v[0], v[1])
	}
	return strings.ToUpper(cc)
}

func fmtNum(a *App, f float64, dec int) string {
	s := fmt.Sprintf("%.*f", dec, f)
	if a.store.Get().Lang != "en" {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

func (a *App) reportText(r Report, now time.Time) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	clock := func(ts int64) string { return time.Unix(ts, 0).Format("15:04") }
	day := func(ts int64) string {
		t := time.Unix(ts, 0)
		if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
			return a.tr("heute ", "today ") + t.Format("15:04")
		}
		return t.Format("02.01. 15:04")
	}
	w(a.tr("RelayPing – Tagesbericht vom %s (letzte 24 Stunden)", "RelayPing – daily report of %s (last 24 hours)"), now.Format("02.01.2006, 15:04"))
	w("")
	if !r.Connected {
		w(a.tr("Achtung: RelayPing ist gerade nicht mit dem Router verbunden.", "Note: RelayPing is not connected to the router right now."))
		w("")
	}
	if len(r.Tunnels) == 0 {
		w(a.tr("Gerade ist kein WireGuard-Tunnel aktiv.", "No WireGuard tunnel is active right now."))
	}
	for _, t := range r.Tunnels {
		w(a.tr("Tunnel „%s“ (%s)", "Tunnel “%s” (%s)"), t.Name, t.Iface)
		since := ""
		if t.Since > 0 {
			since = a.tr(", seit ", ", since ") + day(t.Since)
		}
		w(a.tr("  Verbunden mit: %s – %s, %s%s", "  Connected to: %s – %s, %s%s"), t.Host, t.City, t.Country, since)
		w(a.tr("  Qualität: %s", "  Quality: %s"), strings.ToUpper(t.GradeText))
		if t.Day.Minutes > 0 {
			w(a.tr("  Ping: Ø %s ms (95 %% der Minuten unter %s ms, schnellster %s ms, langsamster %s ms)",
				"  Ping: avg %s ms (95%% of minutes below %s ms, fastest %s ms, slowest %s ms)"),
				fmtNum(a, t.Day.Avg, 1), fmtNum(a, t.Day.P95, 1), fmtNum(a, t.Day.Min, 1), fmtNum(a, t.Day.Max, 1))
			w(a.tr("  Jitter: Ø %s ms   Paketverlust: %s %% (%d von %d Minuten mit Verlust)", "  Jitter: avg %s ms   Packet loss: %s%% (%d of %d minutes with loss)"),
				fmtNum(a, t.Day.Jitter, 1), fmtNum(a, t.Day.Loss, 1), t.Day.BadMins, t.Day.Minutes)
			h := float64(t.Day.Minutes) / 60
			w(a.tr("  Gemessen: %s Stunden", "  Measured: %s hours"), fmtNum(a, h, 1))
		} else {
			w(a.tr("  Noch keine Messwerte für diesen Tunnel.", "  No measurements for this tunnel yet."))
		}
		if t.HSWarn {
			w(a.tr("  Achtung: Es wird gesendet, aber seit %d Minuten kam kein WireGuard-Handshake zustande.", "  Note: traffic is being sent, but no WireGuard handshake for %d minutes."), t.Handshake/60)
		}
		if t.BestHost != "" {
			if t.BestHost == t.Host {
				w(a.tr("  Bester Server im Land laut Bestenliste: dieser (%s ms)", "  Best server in the country per leaderboard: this one (%s ms)"), fmtNum(a, t.BestMedian, 1))
			} else {
				w(a.tr("  Bester Server im Land gerade: %s (%s ms)", "  Best server in the country right now: %s (%s ms)"), t.BestHost, fmtNum(a, t.BestMedian, 1))
			}
		}
		if t.SpeedMbps > 0 {
			w(a.tr("  Letzter Speedtest (Router, Richtwert): %s Mbit/s am %s", "  Last speed test (router, guide value): %s Mbit/s on %s"), fmtNum(a, t.SpeedMbps, 0), time.Unix(t.SpeedAt, 0).Format("02.01. 15:04"))
		}
		if len(t.Servers) > 1 {
			w(a.tr("  Heute genutzte Server: %s", "  Servers used today: %s"), strings.Join(t.Servers, ", "))
		}
		w("")
	}
	var sw, al []DayEvent
	for _, e := range r.Events {
		if e.Kind == "wechsel" {
			sw = append(sw, e)
		} else {
			al = append(al, e)
		}
	}
	w(a.tr("Server-Wechsel (24 h): %d", "Server switches (24 h): %d"), len(sw))
	for _, e := range sw {
		w("  %s  %s", clock(e.T), e.Text)
	}
	w(a.tr("Warnungen (24 h): %d", "Alerts (24 h): %d"), len(al))
	for _, e := range al {
		w("  %s  %s", clock(e.T), e.Text)
	}
	if r.Router != nil {
		up := time.Duration(r.Router["laufzeit_s"].(int64)) * time.Second
		w("")
		w(a.tr("Router: läuft seit %d Tagen %d Stunden", "Router: up %d days %d hours"), int(up.Hours())/24, int(up.Hours())%24)
	}
	return b.String()
}

// writeReport legt relayping-bericht.txt und .json im Datenordner ab.
func (d *Day) writeReport() {
	rep := d.Build(time.Now())
	if b, err := json.MarshalIndent(rep, "", "  "); err == nil {
		writeAtomic(d.app.store.File("relayping-bericht.json"), b)
	}
	writeAtomic(d.app.store.File("relayping-bericht.txt"), []byte("\xef\xbb\xbf"+strings.ReplaceAll(rep.Text, "\n", "\r\n")))
}

func writeAtomic(p string, b []byte) {
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
}

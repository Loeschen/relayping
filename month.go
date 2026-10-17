package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Monatsbericht: Verbrauch, Ausfälle, Ping je Tunnel, Wechsel, Warnungen und
// Speedtests eines Kalendermonats. Am Monatsanfang schreibt RelayPing den
// Bericht des Vormonats als relayping-monatsbericht.txt/.json (und eine Kopie
// in verlauf/), die geplante Mail am 1. verschickt ihn.

type MonthTunnel struct {
	Name    string   `json:"name"`
	Ping    float64  `json:"ping_ms"`
	Jitter  float64  `json:"jitter_ms"`
	Loss    float64  `json:"verlust_prozent"`
	Hours   float64  `json:"gemessen_stunden"`
	Days    int      `json:"tage"`
	Servers []string `json:"server"`
}

type MonthReport struct {
	Month      string         `json:"monat"`
	Generated  int64          `json:"erstellt"`
	Complete   bool           `json:"abgeschlossen"`
	Tunnels    []MonthTunnel  `json:"tunnel"`
	Usage      UsageSum       `json:"verbrauch"`
	UsageDays  int            `json:"verbrauch_tage"`
	Outages    int            `json:"ausfaelle"`
	Downtime   int64          `json:"ausfallzeit_s"`
	Reboots    int            `json:"router_neustarts"`
	Longest    *Outage        `json:"laengster_ausfall,omitempty"`
	Switches   int            `json:"wechsel"`
	Alerts     int            `json:"warnungen"`
	SpeedTests int            `json:"speedtests"`
	AvgDown    float64        `json:"down_mbit"`
	AvgUp      float64        `json:"up_mbit"`
	BestDown   float64        `json:"bester_down_mbit"`
	Grades     map[string]int `json:"ping_unter_last"`
	// FRITZ!Box (falls angebunden)
	FritzRX         uint64         `json:"fritzbox_empfangen,omitempty"`
	FritzTX         uint64         `json:"fritzbox_gesendet,omitempty"`
	FritzDays       int            `json:"fritzbox_tage,omitempty"`
	FritzReconnects int            `json:"fritzbox_neuverbindungen,omitempty"`
	FritzReboots    int            `json:"fritzbox_neustarts,omitempty"`
	Blips           map[string]int `json:"kurzaussetzer"` // internet, tunnel, lan
	Text            string         `json:"text"`
}

func monthName(a *App, m string) string {
	t, err := time.Parse("2006-01", m)
	if err != nil {
		return m
	}
	de := []string{"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"}
	if a.store.Get().Lang == "en" {
		return t.Format("January 2006")
	}
	return fmt.Sprintf("%s %d", de[t.Month()-1], t.Year())
}

// BuildMonth erstellt den Bericht für einen Monat ("2006-01").
func (a *App) BuildMonth(m string, now time.Time) MonthReport {
	r := MonthReport{Month: m, Generated: now.Unix(), Grades: map[string]int{}, Blips: map[string]int{}}
	r.Complete = m < now.Format("2006-01")
	// Ping je Tunnel aus den Tageswerten
	d := a.day
	d.mu.Lock()
	type acc struct {
		DayAgg
		days    int
		servers map[string]bool
	}
	per := map[string]*acc{}
	for day, tm := range d.d.Daily {
		if !strings.HasPrefix(day, m) {
			continue
		}
		for name, ag := range tm {
			x := per[name]
			if x == nil {
				x = &acc{servers: map[string]bool{}}
				per[name] = x
			}
			x.Sent += ag.Sent
			x.Recv += ag.Recv
			x.Sum += ag.Sum
			x.JSum += ag.JSum
			x.JN += ag.JN
			x.Mins += ag.Mins
			x.days++
			if ag.Host != "" {
				x.servers[ag.Host] = true
			}
		}
	}
	counts := map[string]int{}
	for k, v := range d.d.Counts[m] {
		counts[k] = v
	}
	d.mu.Unlock()
	for name, x := range per {
		t := MonthTunnel{Name: name, Days: x.days, Hours: round1(float64(x.Mins) / 60)}
		if x.Recv > 0 {
			t.Ping = round1(x.Sum / float64(x.Recv))
		}
		if x.JN > 0 {
			t.Jitter = round1(x.JSum / float64(x.JN))
		}
		if x.Sent > 0 {
			t.Loss = round1(float64(x.Sent-x.Recv) * 100 / float64(x.Sent))
		}
		for s := range x.servers {
			t.Servers = append(t.Servers, s)
		}
		sort.Strings(t.Servers)
		r.Tunnels = append(r.Tunnels, t)
	}
	sort.Slice(r.Tunnels, func(i, j int) bool { return r.Tunnels[i].Name < r.Tunnels[j].Name })
	r.Switches, r.Alerts = counts["wechsel"], counts["warnung"]
	// Verbrauch
	a.traffic.mu.Lock()
	for k, du := range a.traffic.d.Days {
		if strings.HasPrefix(k, m) {
			r.Usage.add(du)
			r.UsageDays++
		}
	}
	a.traffic.mu.Unlock()
	// Ausfälle
	for _, o := range a.outages.List() {
		if time.Unix(o.Start, 0).Format("2006-01") != m {
			continue
		}
		switch o.Kind {
		case "neustart":
			r.Reboots++
			continue
		case "fritz-neu":
			r.FritzReconnects++
			continue
		case "fritz-neustart":
			r.FritzReboots++
			continue
		case "kurz-internet", "kurz-tunnel", "kurz-lan", "kurz-dns":
			r.Blips[strings.TrimPrefix(o.Kind, "kurz-")] += max(1, o.Count)
			continue
		}
		r.Outages++
		if o.End > o.Start {
			r.Downtime += o.End - o.Start
			if r.Longest == nil || o.End-o.Start > r.Longest.End-r.Longest.Start {
				oo := o
				r.Longest = &oo
			}
		}
	}
	if a.fritz != nil {
		r.FritzRX, r.FritzTX, r.FritzDays = a.fritz.MonthUsage(m)
	}
	// Speedtests (PC)
	var sd, su float64
	for _, p := range a.pctest.History() {
		if p.Finished.Format("2006-01") != m || p.Error != "" {
			continue
		}
		r.SpeedTests++
		sd += p.Down
		su += p.Up
		if p.Down > r.BestDown {
			r.BestDown = p.Down
		}
		if p.Grade != "" {
			r.Grades[p.Grade]++
		}
	}
	if r.SpeedTests > 0 {
		r.AvgDown, r.AvgUp = round1(sd/float64(r.SpeedTests)), round1(su/float64(r.SpeedTests))
	}
	r.Text = a.monthText(r)
	return r
}

func (a *App) monthText(r MonthReport) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	gb := func(v uint64) string { return fmtNum(a, float64(v)/1e9, 1) + " GB" }
	title := a.tr("RelayPing – Monatsbericht %s", "RelayPing – monthly report %s")
	w(title, monthName(a, r.Month))
	if !r.Complete {
		w(a.tr("(bisheriger Stand, Monat läuft noch)", "(so far, month still running)"))
	}
	w("")
	tot, vpn := r.Usage.RX+r.Usage.TX, r.Usage.VPNRX+r.Usage.VPNTX
	if vpn <= tot {
		w(a.tr("Datenverbrauch: %s (↓ %s, ↑ %s), davon durch Tunnel %s", "Data used: %s (↓ %s, ↑ %s), through tunnels %s"),
			gb(tot), gb(r.Usage.RX), gb(r.Usage.TX), gb(vpn))
	} else {
		// Hardware-Beschleunigung: der Internet-Zähler sieht nicht alles
		w(a.tr("Datenverbrauch: mindestens %s (durch Tunnel gezählt; der Internet-Zähler zeigt nur %s – vermutlich Hardware-Beschleunigung)",
			"Data used: at least %s (counted through tunnels; the internet counter only shows %s – probably hardware offloading)"), gb(vpn), gb(tot))
	}
	if r.UsageDays == 1 {
		w(a.tr("  gezählt an 1 Tag", "  counted on 1 day"))
	} else if r.UsageDays > 1 {
		w(a.tr("  gezählt an %d Tagen", "  counted on %d days"), r.UsageDays)
	}
	w("")
	for _, t := range r.Tunnels {
		w(a.tr("Tunnel „%s“: Ø %s ms Ping, %s ms Jitter, %s %% Verlust (%s h gemessen an %d Tagen)", "Tunnel “%s”: avg %s ms ping, %s ms jitter, %s%% loss (%s h measured on %d days)"),
			t.Name, fmtNum(a, t.Ping, 1), fmtNum(a, t.Jitter, 1), fmtNum(a, t.Loss, 1), fmtNum(a, t.Hours, 1), t.Days)
		if len(t.Servers) > 0 {
			w(a.tr("  Server: %s", "  Servers: %s"), strings.Join(t.Servers, ", "))
		}
	}
	if len(r.Tunnels) > 0 {
		w("")
	}
	w(a.tr("Ausfälle: %d, zusammen %s", "Outages: %d, total %s"), r.Outages, durText(a, r.Downtime))
	if r.Longest != nil {
		w(a.tr("  längster: %s am %s", "  longest: %s on %s"), a.outageText(*r.Longest), time.Unix(r.Longest.Start, 0).Format("02.01. 15:04"))
	}
	w(a.tr("Kurzaussetzer: %d Internet, %d Tunnel, %d PC ↔ Router, %d DNS", "Short dropouts: %d internet, %d tunnel, %d PC ↔ router, %d DNS"), r.Blips["internet"], r.Blips["tunnel"], r.Blips["lan"], r.Blips["dns"])
	w(a.tr("Router-Neustarts: %d", "Router restarts: %d"), r.Reboots)
	if r.FritzDays > 0 || r.FritzReconnects > 0 || r.FritzReboots > 0 {
		w(a.tr("FRITZ!Box: %s (↓ %s, ↑ %s) an %d Tagen, %d Neuverbindungen, %d Neustarts",
			"FRITZ!Box: %s (↓ %s, ↑ %s) on %d days, %d reconnects, %d restarts"),
			gb(r.FritzRX+r.FritzTX), gb(r.FritzRX), gb(r.FritzTX), r.FritzDays, r.FritzReconnects, r.FritzReboots)
	}
	w(a.tr("Server-Wechsel: %d   Warnungen: %d", "Server switches: %d   Alerts: %d"), r.Switches, r.Alerts)
	if r.SpeedTests > 0 {
		w(a.tr("Speedtests: %d, Ø ↓ %s / ↑ %s Mbit/s, bester ↓ %s Mbit/s", "Speed tests: %d, avg ↓ %s / ↑ %s Mbit/s, best ↓ %s Mbit/s"),
			r.SpeedTests, fmtNum(a, r.AvgDown, 0), fmtNum(a, r.AvgUp, 0), fmtNum(a, r.BestDown, 0))
		var gs []string
		for _, g := range []string{"A", "B", "C", "D"} {
			if n := r.Grades[g]; n > 0 {
				gs = append(gs, fmt.Sprintf("%s×%d", g, n))
			}
		}
		if len(gs) > 0 {
			w(a.tr("  Ping unter Last: %s", "  Ping under load: %s"), strings.Join(gs, ", "))
		}
	} else {
		w(a.tr("Speedtests: keine", "Speed tests: none"))
	}
	return b.String()
}

// writeMonthIfDue schreibt den Bericht des Vormonats, sobald ein neuer Monat beginnt.
func (d *Day) writeMonthIfDue(now time.Time) {
	a := d.app
	prev := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, -1, 0).Format("2006-01")
	p := a.store.File("relayping-monatsbericht.json")
	var old struct {
		M string `json:"monat"`
	}
	if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &old) == nil && old.M == prev {
		return
	}
	r := a.BuildMonth(prev, now)
	if r.UsageDays == 0 && len(r.Tunnels) == 0 && r.Outages == 0 && r.SpeedTests == 0 {
		return // für diesen Monat gibt es keine Daten
	}
	if b, err := json.MarshalIndent(r, "", "  "); err == nil {
		writeAtomic(p, b)
	}
	txt := []byte("\xef\xbb\xbf" + strings.ReplaceAll(r.Text, "\n", "\r\n"))
	writeAtomic(a.store.File("relayping-monatsbericht.txt"), txt)
	dir := a.store.File("verlauf")
	_ = os.MkdirAll(dir, 0o755)
	writeAtomic(filepath.Join(dir, "monatsbericht-"+prev+".txt"), txt)
	a.log.Printf("Monatsbericht %s geschrieben", prev)
}

package main

import (
	"fmt"
	"sync"
	"time"
)

// Warnungen: Ist der aktive Server eines Tunnels über mehrere Minuten deutlich
// schlechter als der beste Server im selben Land (oder verliert er Pakete),
// meldet RelayPing das in der Oberfläche und als Windows-Benachrichtigung.

type Alert struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Iface   string    `json:"iface"`
	Tunnel  string    `json:"tunnel"`
	Host    string    `json:"host"`
	Better  string    `json:"better,omitempty"`
	Kind    string    `json:"kind"`  // loss oder slow – die Oberfläche formuliert den Text selbst
	Value   float64   `json:"value"` // Verlust in % bzw. Ø ms
	BestAvg float64   `json:"best_avg,omitempty"`
	Text    string    `json:"text"`
	Cleared bool      `json:"cleared"`
}

type Alerts struct {
	app    *App
	mu     sync.Mutex
	list   []Alert
	strike map[string]int       // iface -> aufeinanderfolgende schlechte Prüfungen
	last   map[string]time.Time // iface -> letzte Warnung (Pause 30 min)
	open   map[string]bool      // iface -> Warnung aktiv
	nextID int64
}

func newAlerts(a *App) *Alerts {
	return &Alerts{app: a, strike: map[string]int{}, last: map[string]time.Time{}, open: map[string]bool{}}
}

func (al *Alerts) List() []Alert {
	al.mu.Lock()
	defer al.mu.Unlock()
	return append([]Alert(nil), al.list...)
}

func (al *Alerts) Dismiss(id int64) {
	al.mu.Lock()
	for i := range al.list {
		if al.list[i].ID == id || id == 0 {
			al.list[i].Cleared = true
		}
	}
	al.mu.Unlock()
	al.app.broadcast("alerts", al.List())
}

// verdict entscheidet, ob ein Tunnel als schlecht gilt (testbar, ohne Seiteneffekte).
func verdict(win WindowStats, bestAvg float64, haveBest bool, lossPct int, extraMs float64) (bad bool, why string) {
	if win.N < 60 { // mindestens eine Minute Messwerte
		return false, ""
	}
	if win.Loss >= float64(lossPct) {
		return true, fmt.Sprintf("loss:%.0f", win.Loss)
	}
	if haveBest && win.Recv > 0 && win.Avg-bestAvg >= extraMs && win.Avg >= bestAvg*1.5 {
		return true, fmt.Sprintf("slow:%.1f:%.1f", win.Avg, bestAvg)
	}
	return false, ""
}

func (al *Alerts) Run() {
	for !al.app.quitting() {
		time.Sleep(30 * time.Second)
		al.check()
	}
}

func (al *Alerts) check() {
	a := al.app
	cfg := a.store.Get()
	ok, _, inf := a.router.State()
	if !ok || !cfg.Alerts || a.speed.Busy() || a.switcher.Status().Running {
		return
	}
	for _, t := range inf.Tunnels {
		if t.Host == "" {
			continue
		}
		m := a.monitor(t.Host)
		if m == nil {
			continue
		}
		win := m.Window(3 * time.Minute)
		bestHost, bestAvg, haveBest := "", 0.0, false
		if b, ok := a.board.Best(t.CC); ok {
			bestHost, bestAvg, haveBest = b.Host, b.Median, true
		} else if s, ok := a.scanner.Best(t.CC); ok {
			bestHost, bestAvg, haveBest = s.Host, s.Avg, true
		}
		if bestHost == t.Host {
			haveBest = false // der aktive Server ist selbst der beste
		}
		bad, why := verdict(win, bestAvg, haveBest, cfg.AlertLossPct, cfg.AlertExtraMs)
		name := t.Name
		if name == "" {
			name = t.Iface
		}
		al.mu.Lock()
		if !bad {
			al.strike[t.Iface] = 0
			if al.open[t.Iface] {
				al.open[t.Iface] = false
				for i := range al.list {
					if al.list[i].Iface == t.Iface {
						al.list[i].Cleared = true
					}
				}
				al.mu.Unlock()
				a.broadcast("alerts", al.List())
				continue
			}
			al.mu.Unlock()
			continue
		}
		al.strike[t.Iface]++
		fire := al.strike[t.Iface] >= 2 && time.Since(al.last[t.Iface]) > 30*time.Minute
		if !fire {
			al.mu.Unlock()
			continue
		}
		al.last[t.Iface] = time.Now()
		al.open[t.Iface] = true
		var text string
		kind, val := "slow", win.Avg
		if why[:4] == "loss" {
			kind, val = "loss", win.Loss
			text = fmt.Sprintf(a.tr("Tunnel „%s“: %s verliert %.0f %% der Pakete.", "Tunnel “%s”: %s is losing %.0f%% of packets."), name, t.Host, win.Loss)
		} else {
			text = fmt.Sprintf(a.tr("Tunnel „%s“: %s braucht %.0f ms, %s nur %.0f ms.", "Tunnel “%s”: %s takes %.0f ms, %s only %.0f ms."), name, t.Host, win.Avg, bestHost, bestAvg)
		}
		if bestHost != "" && bestHost != t.Host {
			text += " " + fmt.Sprintf(a.tr("Vorschlag: auf %s wechseln.", "Suggestion: switch to %s."), bestHost)
		}
		al.nextID++
		al.list = append(al.list, Alert{ID: al.nextID, Time: time.Now(), Iface: t.Iface, Tunnel: name, Host: t.Host, Better: bestHost, Kind: kind, Value: val, BestAvg: bestAvg, Text: text})
		if len(al.list) > 30 {
			al.list = al.list[len(al.list)-30:]
		}
		al.mu.Unlock()
		a.broadcast("alerts", al.List())
		a.notify(a.tr("RelayPing: Tunnel langsam", "RelayPing: tunnel degraded"), text)
	}
}

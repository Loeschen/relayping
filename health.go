package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- Gesamtzustand (Statusleiste + Taskleisten-Symbol) ----------

type HealthItem struct {
	Key   string  `json:"key"`   // internet, tunnel:<iface>, router
	Label string  `json:"label"` // z. B. Tunnel-Name
	Level int     `json:"level"` // 0 ok, 1 Warnung, 2 Problem, -1 unbekannt
	Ping  float64 `json:"ping,omitempty"`
	Host  string  `json:"host,omitempty"`
	Text  string  `json:"text,omitempty"`
}

type Health struct {
	Level int          `json:"level"`
	Items []HealthItem `json:"items"`
	Tip   string       `json:"tip"`
}

func (a *App) health() Health {
	ok, _, inf := a.router.State()
	h := Health{Level: 0}
	worst := func(l int) {
		if l > h.Level {
			h.Level = l
		}
	}
	if a.localMode() {
		return a.localHealth()
	}
	if !ok {
		h.Level = 2
		h.Items = append(h.Items, HealthItem{Key: "router", Label: a.tr("Router", "Router"), Level: 2, Text: a.tr("nicht verbunden", "not connected")})
		h.Tip = "RelayPing – " + a.tr("Router nicht verbunden", "router not connected")
		return h
	}
	net := HealthItem{Key: "internet", Label: "Internet", Level: -1}
	switch inf.WANOK {
	case 1:
		net.Level = 0
	case 0:
		net.Level = 2
		net.Text = a.tr("keine Antwort", "no answer")
	}
	worst(net.Level)
	h.Items = append(h.Items, net)
	openAlerts := map[string]bool{}
	for _, al := range a.alerts.List() {
		if !al.Cleared {
			openAlerts[al.Iface] = true
		}
	}
	var tips []string
	for _, t := range inf.Tunnels {
		name := t.Name
		if name == "" {
			name = t.Iface
		}
		it := HealthItem{Key: "tunnel:" + t.Iface, Label: name, Host: t.Host, Level: -1}
		if m := a.monitor(t.Host); m != nil {
			if w := m.Window(time.Minute); w.N > 10 {
				it.Ping = round1(w.Avg)
				it.Level = 0
				if w.Loss >= 5 {
					it.Level = 1
					it.Text = fmt.Sprintf(a.tr("%.0f %% Verlust", "%.0f%% loss"), w.Loss)
				}
			}
		}
		if t.Probe == 0 {
			it.Level = 2
			it.Text = a.tr("Tunnel antwortet nicht", "tunnel not responding")
		} else if t.Probe == 1 && it.Level < 0 {
			it.Level = 0
		}
		if openAlerts[t.Iface] && it.Level < 1 {
			it.Level = 1
			if it.Text == "" {
				it.Text = a.tr("Warnung", "alert")
			}
		}
		worst(it.Level)
		h.Items = append(h.Items, it)
		tip := name + ": " + t.Host
		if it.Ping > 0 {
			tip += fmt.Sprintf(" %.0f ms", it.Ping)
		}
		if it.Text != "" {
			tip += " (" + it.Text + ")"
		}
		tips = append(tips, tip)
	}
	if a.fritz != nil && a.store.Get().FritzOn {
		fs := a.fritz.State()
		it := HealthItem{Key: "fritz", Label: "FRITZ!Box", Level: -1}
		switch {
		case !fs.OK && fs.Checked > 0:
			it.Level, it.Text = 1, a.tr("nicht erreichbar", "not reachable")
		case fs.Conn == "Connected":
			it.Level = 0
		case fs.Conn != "":
			it.Level, it.Text = 2, a.tr("offline", "offline")
			tips = append([]string{a.tr("FRITZ!Box offline", "FRITZ!Box offline")}, tips...)
		}
		worst(it.Level)
		h.Items = append(h.Items, it)
	}
	if net.Level == 2 {
		tips = append([]string{a.tr("Internet ausgefallen", "Internet down")}, tips...)
	}
	h.Tip = "RelayPing\n" + strings.Join(tips, "\n")
	if len(h.Tip) > 120 {
		h.Tip = h.Tip[:120]
	}
	return h
}

// localHealth: im PC-Modus zählt, ob die live beobachteten Server antworten.
func (a *App) localHealth() Health {
	h := Health{Level: -1}
	a.mu.Lock()
	mons := make([]*Monitor, 0, len(a.monitors))
	for _, m := range a.monitors {
		mons = append(mons, m)
	}
	a.mu.Unlock()
	sort.Slice(mons, func(i, j int) bool { return mons[i].relay.Host < mons[j].relay.Host })
	tips := []string{"RelayPing (" + a.tr("PC-Messung", "PC measurement") + ")"}
	allDown, any := true, false
	for _, m := range mons {
		w := m.Window(time.Minute)
		if w.N <= 10 {
			continue
		}
		any = true
		it := HealthItem{Key: "server:" + m.relay.Host, Label: m.relay.Host, Level: 0, Ping: round1(w.Avg), Host: m.relay.Host}
		if w.Loss >= 100 {
			it.Level, it.Text = 2, a.tr("keine Antwort", "no answer")
		} else {
			allDown = false
			if w.Loss >= 5 {
				it.Level, it.Text = 1, fmt.Sprintf(a.tr("%.0f %% Verlust", "%.0f%% loss"), w.Loss)
			}
		}
		if it.Level > h.Level {
			h.Level = it.Level
		}
		h.Items = append(h.Items, it)
		tips = append(tips, fmt.Sprintf("%s %.0f ms", m.relay.Host, w.Avg))
	}
	if any && allDown {
		h.Level = 2
	}
	if h.Level < 0 {
		h.Level = 0
	}
	h.Tip = strings.Join(tips, "\n")
	if len(h.Tip) > 120 {
		h.Tip = h.Tip[:120]
	}
	return h
}

func (a *App) updateTray() {
	h := a.health()
	a.tray.SetStatus(h.Level, h.Tip)
}

// ---------- Router-Verlauf (24 h, Minutenwerte) ----------

type RouterPoint struct {
	T    int64   `json:"t"`
	CPU  float64 `json:"cpu"`
	RAM  float64 `json:"ram"`
	Temp float64 `json:"temp"`
}

type RouterHist struct {
	mu       sync.Mutex
	file     string
	pts      []RouterPoint
	cur      RouterPoint
	n        int
	lastSave time.Time
}

func newRouterHist(file string) *RouterHist {
	h := &RouterHist{file: file}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &h.pts)
	}
	return h
}

func (h *RouterHist) Add(inf RouterInfo, now time.Time) {
	if inf.UptimeS == 0 {
		return
	}
	cpu := -1.0
	if inf.NProc > 0 {
		cpu = inf.Load1 / float64(inf.NProc) * 100
		if cpu > 100 {
			cpu = 100
		}
	}
	ram := -1.0
	if inf.MemTotal > 0 {
		ram = (1 - float64(inf.MemAvail)/float64(inf.MemTotal)) * 100
	}
	min := now.Truncate(time.Minute).Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur.T != min && h.n > 0 {
		p := h.cur
		p.CPU, p.RAM, p.Temp = round1(p.CPU/float64(h.n)), round1(p.RAM/float64(h.n)), round1(p.Temp/float64(h.n))
		h.pts = append(h.pts, p)
		cut := now.Add(-24 * time.Hour).Unix()
		i := 0
		for i < len(h.pts) && h.pts[i].T < cut {
			i++
		}
		h.pts = h.pts[i:]
		h.cur, h.n = RouterPoint{}, 0
		if time.Since(h.lastSave) > 10*time.Minute {
			if b, err := json.Marshal(h.pts); err == nil {
				writeAtomic(h.file, b)
			}
			h.lastSave = time.Now()
		}
	}
	h.cur.T = min
	h.cur.CPU += cpu
	h.cur.RAM += ram
	h.cur.Temp += inf.TempC
	h.n++
}

func (h *RouterHist) List() []RouterPoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]RouterPoint{}, h.pts...)
}

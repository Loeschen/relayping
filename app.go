package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type App struct {
	store    *Store
	relays   *Relays
	router   *Router
	scanner  *Scanner
	board    *Board
	hist     *History
	alerts   *Alerts
	switcher *Switcher
	speed    *Speed
	day      *Day
	geo      *Geo
	csv      *CSVLog
	tray     Tray
	log      *Logger

	mu       sync.Mutex
	monitors map[string]*Monitor
	clients  map[chan []byte]bool
	quit     chan struct{}
	quitOnce sync.Once
	token    string
	addr     string
	relayErr string
	started  bool
}

func newApp(dir string) *App {
	a := &App{
		store:    loadStore(dir),
		monitors: map[string]*Monitor{},
		clients:  map[chan []byte]bool{},
		quit:     make(chan struct{}),
	}
	a.log = newLogger(a.store.File("relayping.log"))
	a.relays = newRelays(a.store.File("relayping-server.json"))
	a.router = &Router{app: a}
	a.scanner = &Scanner{app: a}
	a.board = newBoard(a)
	a.hist = newHistory(a.store.File("relayping-verlauf.json"))
	a.alerts = newAlerts(a)
	a.switcher = &Switcher{app: a}
	a.speed = newSpeed(a, a.store.File("relayping-speed.json"))
	a.day = newDay(a, a.store.File("relayping-tag.json"))
	a.geo = newGeo(a, a.store.File("relayping-laender.json"))
	a.csv = &CSVLog{app: a}
	a.tray = noTray{}
	return a
}

func (a *App) Quit() {
	a.quitOnce.Do(func() { close(a.quit) })
}

func (a *App) quitting() bool {
	select {
	case <-a.quit:
		return true
	default:
		return false
	}
}

func (a *App) notify(title, msg string) {
	a.log.Printf("Hinweis: %s – %s", title, msg)
	a.tray.Notify(title, msg)
}

// ---------- Live-Ereignisse (Server-Sent Events) ----------

func (a *App) broadcast(event string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	msg := []byte("event: " + event + "\ndata: " + string(b) + "\n\n")
	a.mu.Lock()
	defer a.mu.Unlock()
	for c := range a.clients {
		select {
		case c <- msg:
		default:
		}
	}
}

func (a *App) pushState() { a.broadcast("state", a.State()) }

type MonitorInfo struct {
	Relay
	Status string `json:"status"`
}

type StateResp struct {
	Version     string              `json:"version"`
	Platform    string              `json:"platform"`
	Connected   bool                `json:"connected"`
	HasKey      bool                `json:"has_key"`
	Error       string              `json:"error,omitempty"`
	Router      RouterInfo          `json:"router"`
	Host        string              `json:"router_host"`
	Port        int                 `json:"router_port"`
	User        string              `json:"router_user"`
	Fingerprint string              `json:"fingerprint,omitempty"`
	Monitors    []MonitorInfo       `json:"monitors"`
	LogCSV      bool                `json:"log_csv"`
	Countries   []string            `json:"countries"`
	ScanPings   int                 `json:"scan_pings"`
	RelayCount  int                 `json:"relay_count"`
	RelayDate   time.Time           `json:"relay_date"`
	RelaySource string              `json:"relay_source"`
	RelayError  string              `json:"relay_error,omitempty"`
	DataDir     string              `json:"data_dir"`
	Lang        string              `json:"lang"`
	Alerts      bool                `json:"alerts"`
	AlertLoss   int                 `json:"alert_loss"`
	AlertExtra  float64             `json:"alert_extra_ms"`
	AutoScanMin int                 `json:"auto_scan_min"`
	BoardOn     bool                `json:"board_on"`
	BoardCC     []string            `json:"board_countries"`
	BoardSec    int                 `json:"board_interval"`
	ChartScale  string              `json:"chart_scale"`
	Favorites   map[string][]string `json:"favorites"`
	Switch      map[string]any      `json:"switch"`
	Autostart   *bool               `json:"autostart,omitempty"` // nur unter Windows
}

func (a *App) State() StateResp {
	conn, errText, inf := a.router.State()
	c := a.store.Get()
	n, t, src := a.relays.Info()
	a.mu.Lock()
	var mons []MonitorInfo
	for _, m := range a.monitors {
		mons = append(mons, MonitorInfo{Relay: m.relay, Status: m.Status()})
	}
	relayErr := a.relayErr
	a.mu.Unlock()
	sort.Slice(mons, func(i, j int) bool { return mons[i].Host < mons[j].Host })
	if inf.Tunnels == nil {
		inf.Tunnels = []Tunnel{}
	}
	st := StateResp{
		Version: version, Platform: runtime.GOOS, Connected: conn, HasKey: a.router.HasKey(), Error: errText,
		Router: inf, Host: c.RouterHost, Port: c.RouterPort, User: c.RouterUser,
		Fingerprint: fingerprint(c.HostKey), Monitors: mons, LogCSV: c.LogCSV,
		Countries: c.Countries, ScanPings: c.ScanPings,
		RelayCount: n, RelayDate: t, RelaySource: src, RelayError: relayErr,
		DataDir: a.store.dir, Lang: c.Lang, Alerts: c.Alerts, AlertLoss: c.AlertLossPct, AlertExtra: c.AlertExtraMs,
		AutoScanMin: c.AutoScanMin, BoardOn: c.BoardOn, BoardCC: c.BoardCountries, BoardSec: c.BoardInterval,
		ChartScale: c.ChartScale, Favorites: c.Favorites, Switch: a.switchInfo(),
	}
	if v, ok := autostartEnabled(); ok {
		st.Autostart = &v
	}
	return st
}

// ---------- Live-Beobachtung ----------

func (a *App) monitor(host string) *Monitor {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.monitors[host]
}

func (a *App) startMonitor(host string, remember bool) error {
	rl, ok := a.relays.Host(host)
	if !ok {
		return fmt.Errorf(a.tr("Unbekannter Server: %s", "Unknown server: %s"), host)
	}
	limit := maxMonitors
	if a.activeHosts()[host] {
		limit += 2 // Tunnel-Server werden immer beobachtet
	}
	a.mu.Lock()
	if _, ok := a.monitors[host]; ok {
		a.mu.Unlock()
		return nil
	}
	if len(a.monitors) >= limit {
		a.mu.Unlock()
		return fmt.Errorf(a.tr("Höchstens %d Server gleichzeitig live", "At most %d servers live at once"), maxMonitors)
	}
	m := newMonitor(a, rl)
	a.monitors[host] = m
	a.mu.Unlock()
	go m.Run()
	if remember {
		a.saveWatch()
	}
	a.pushState()
	return nil
}

func (a *App) stopMonitor(host string) {
	a.mu.Lock()
	m, ok := a.monitors[host]
	delete(a.monitors, host)
	a.mu.Unlock()
	if ok {
		m.Stop()
		a.saveWatch()
		a.pushState()
	}
}

func (a *App) stopAllMonitors() {
	a.mu.Lock()
	ms := a.monitors
	a.monitors = map[string]*Monitor{}
	a.mu.Unlock()
	for _, m := range ms {
		m.Stop()
	}
}

func (a *App) saveWatch() {
	a.mu.Lock()
	var hs []string
	for h := range a.monitors {
		hs = append(hs, h)
	}
	a.mu.Unlock()
	sort.Strings(hs)
	_ = a.store.Update(func(c *Config) { c.Watch = hs })
}

func (a *App) activeIPs() map[string]bool {
	_, _, inf := a.router.State()
	m := map[string]bool{}
	for _, t := range inf.Tunnels {
		m[t.IP] = true
	}
	return m
}

func (a *App) activeHosts() map[string]bool {
	_, _, inf := a.router.State()
	m := map[string]bool{}
	for _, t := range inf.Tunnels {
		if t.Host != "" {
			m[t.Host] = true
		}
	}
	return m
}

// ---------- Favoriten ----------

func (a *App) saveFavorite(name string, hosts []string) error {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 40 {
		return errors.New(a.tr("Name: 1 bis 40 Zeichen", "Name: 1 to 40 characters"))
	}
	var clean []string
	seen := map[string]bool{}
	for _, h := range hosts {
		if _, ok := a.relays.Host(h); ok && !seen[h] {
			seen[h] = true
			clean = append(clean, h)
		}
	}
	if len(clean) == 0 {
		return errors.New(a.tr("Keine gültigen Server in der Auswahl", "No valid servers in the selection"))
	}
	if len(clean) > maxMonitors {
		clean = clean[:maxMonitors]
	}
	return a.store.Update(func(c *Config) {
		if len(c.Favorites) >= 20 {
			if _, exists := c.Favorites[name]; !exists {
				return
			}
		}
		c.Favorites[name] = clean
	})
}

// applyFavorite schaltet die Server einer Gruppe live (Tunnel-Server bleiben).
func (a *App) applyFavorite(name string) error {
	hosts, ok := a.store.Get().Favorites[name]
	if !ok {
		return errors.New(a.tr("Favorit nicht gefunden", "Favorite not found"))
	}
	keep := a.activeHosts()
	for _, h := range hosts {
		keep[h] = true
	}
	a.mu.Lock()
	var drop []string
	for h := range a.monitors {
		if !keep[h] {
			drop = append(drop, h)
		}
	}
	a.mu.Unlock()
	for _, h := range drop {
		a.stopMonitor(h)
	}
	var lastErr error
	for _, h := range hosts {
		if err := a.startMonitor(h, true); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// ---------- Verbindung ----------

// onConnected: aktive Tunnel-Server und zuletzt beobachtete Server live starten,
// danach Router-Zustand alle 10 s und GL-Tunnel alle 60 s auffrischen.
func (a *App) onConnected() {
	go a.router.RefreshGL(true)
	_, _, inf := a.router.State()
	for _, t := range inf.Tunnels {
		if t.Host != "" {
			a.startMonitor(t.Host, false)
		}
	}
	for _, h := range a.store.Get().Watch {
		a.startMonitor(h, false)
	}
	a.board.Restart()
	a.pushState()
	a.mu.Lock()
	first := !a.started
	a.started = true
	a.mu.Unlock()
	if !first {
		return
	}
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		n := 0
		for range t.C {
			if a.quitting() {
				return
			}
			if ok, _, _ := a.router.State(); !ok {
				continue
			}
			n++
			if n%6 == 0 {
				a.router.RefreshGL(false)
			}
			a.router.Refresh()
			// neue Tunnel-Server automatisch live beobachten
			_, _, inf := a.router.State()
			a.day.Tunnels(inf.Tunnels, time.Now())
			for _, t := range inf.Tunnels {
				if t.Host != "" && a.monitor(t.Host) == nil {
					a.startMonitor(t.Host, false)
				}
			}
		}
	}()
}

// backfill: bisherige Live-Messwerte aller beobachteten Server.
func (a *App) backfill() map[string][][2]float64 {
	a.mu.Lock()
	mons := make([]*Monitor, 0, len(a.monitors))
	for _, m := range a.monitors {
		mons = append(mons, m)
	}
	a.mu.Unlock()
	out := map[string][][2]float64{}
	for _, m := range mons {
		out[m.relay.Host] = m.Recent()
	}
	return out
}

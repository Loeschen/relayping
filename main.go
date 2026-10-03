package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui
var uiFS embed.FS

const version = "0.9.0-beta"

type App struct {
	store   *Store
	relays  *Relays
	router  *Router
	scanner *Scanner
	csv     *CSVLog

	mu       sync.Mutex
	monitors map[string]*Monitor
	clients  map[chan []byte]bool
	quit     chan struct{}
	token    string
	addr     string
	relayErr string
}

func main() {
	setupConsole()
	dir := dataDir()
	app := &App{
		store:    loadStore(dir),
		monitors: map[string]*Monitor{},
		clients:  map[chan []byte]bool{},
		quit:     make(chan struct{}),
	}
	app.relays = newRelays(app.store.File("relayping-server.json"))
	app.router = &Router{app: app}
	app.scanner = &Scanner{app: app}
	app.csv = &CSVLog{app: app}
	b := make([]byte, 16)
	rand.Read(b)
	app.token = hex.EncodeToString(b)

	ln, err := net.Listen("tcp", "127.0.0.1:"+envOr("MLAT_PORT", "47321"))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("Fehler: kein freier Port:", err)
			waitEnter()
			return
		}
	}
	app.addr = ln.Addr().String()
	url := "http://" + app.addr + "/?k=" + app.token

	fmt.Println("RelayPing " + version + " – inoffizielles Tool, nicht mit Mullvad VPN AB oder GL.iNet verbunden")
	fmt.Println("Oberfläche:  http://" + app.addr)
	fmt.Println("Daten:       " + dir)
	fmt.Println()
	fmt.Println("Dieses Fenster offen lassen. Schließen beendet das Programm.")

	go func() {
		if err := app.relays.Load(false); err != nil {
			app.mu.Lock()
			app.relayErr = err.Error()
			app.mu.Unlock()
			fmt.Println("Hinweis:", err)
		}
		app.pushState()
		if app.router.HasKey() {
			if err := app.router.ConnectKey(); err != nil && !errors.Is(err, errHostKeyChanged) {
				app.router.EnsureReconnect()
			}
		}
	}()

	if os.Getenv("MLAT_NO_BROWSER") == "" {
		go func() { time.Sleep(400 * time.Millisecond); openBrowser(url) }()
	} else {
		fmt.Println("URL: " + url)
	}

	srv := &http.Server{Handler: app.routes(), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	<-app.quit
	app.stopAllMonitors()
	app.router.Disconnect()
	time.Sleep(300 * time.Millisecond)
}

func (a *App) quitting() bool {
	select {
	case <-a.quit:
		return true
	default:
		return false
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Println("Bitte im Browser öffnen:", url)
	}
}

func waitEnter() {
	fmt.Println("Enter drücken zum Beenden.")
	var s string
	fmt.Scanln(&s)
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
	Version     string        `json:"version"`
	Connected   bool          `json:"connected"`
	HasKey      bool          `json:"has_key"`
	Error       string        `json:"error,omitempty"`
	Router      RouterInfo    `json:"router"`
	Host        string        `json:"router_host"`
	Port        int           `json:"router_port"`
	User        string        `json:"router_user"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Monitors    []MonitorInfo `json:"monitors"`
	LogCSV      bool          `json:"log_csv"`
	Countries   []string      `json:"countries"`
	ScanPings   int           `json:"scan_pings"`
	RelayCount  int           `json:"relay_count"`
	RelayDate   time.Time     `json:"relay_date"`
	RelaySource string        `json:"relay_source"`
	RelayError  string        `json:"relay_error,omitempty"`
	DataDir     string        `json:"data_dir"`
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
	return StateResp{
		Version: version, Connected: conn, HasKey: a.router.HasKey(), Error: errText,
		Router: inf, Host: c.RouterHost, Port: c.RouterPort, User: c.RouterUser,
		Fingerprint: fingerprint(c.HostKey), Monitors: mons, LogCSV: c.LogCSV,
		Countries: c.Countries, ScanPings: c.ScanPings,
		RelayCount: n, RelayDate: t, RelaySource: src, RelayError: relayErr,
		DataDir: a.store.dir,
	}
}

// ---------- Live-Beobachtung ----------

func (a *App) startMonitor(host string, remember bool) error {
	rl, ok := a.relays.Host(host)
	if !ok {
		return fmt.Errorf("Unbekannter Server: %s", host)
	}
	a.mu.Lock()
	if _, ok := a.monitors[host]; ok {
		a.mu.Unlock()
		return nil
	}
	if len(a.monitors) >= maxMonitors {
		a.mu.Unlock()
		return fmt.Errorf("Höchstens %d Server gleichzeitig live", maxMonitors)
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

// Nach dem Verbinden: aktive Tunnel-Server und zuletzt beobachtete Server live starten.
func (a *App) onConnected() {
	_, _, inf := a.router.State()
	for _, t := range inf.Tunnels {
		if t.Host != "" {
			a.startMonitor(t.Host, false)
		}
	}
	for _, h := range a.store.Get().Watch {
		a.startMonitor(h, false)
	}
	a.pushState()
	go func() {
		// Tunnel-Zuordnung regelmäßig auffrischen (z. B. nach manuellem Serverwechsel)
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if a.quitting() {
				return
			}
			if ok, _, _ := a.router.State(); !ok {
				return
			}
			a.router.Refresh()
		}
	}()
}

// ---------- HTTP ----------

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	static := http.FileServer(http.FS(sub))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if k := r.URL.Query().Get("k"); k != "" {
			if k == a.token {
				http.SetCookie(w, &http.Cookie{Name: "mlat", Value: a.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
		if !a.authed(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;background:#0d1321;color:#e6ebf5;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><h2>RelayPing</h2><p>Bitte über die RelayPing.exe öffnen – sie öffnet diese Seite mit dem passenden Schlüssel.</p></div>`)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, r)
	})

	api := func(path string, h func(w http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if !a.authed(r) {
				http.Error(w, "nicht berechtigt", http.StatusForbidden)
				return
			}
			if r.Method != http.MethodGet && r.Header.Get("X-MLat") != "1" {
				http.Error(w, "nicht berechtigt", http.StatusForbidden)
				return
			}
			h(w, r)
		})
	}

	api("/api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.State()) })
	api("/api/relays", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.relays.All()) })
	api("/api/scan", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.scanner.State()) })

	api("/api/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "kein Streaming", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		ch := make(chan []byte, 256)
		a.mu.Lock()
		a.clients[ch] = true
		a.mu.Unlock()
		defer func() { a.mu.Lock(); delete(a.clients, ch); a.mu.Unlock() }()
		b, _ := json.Marshal(a.State())
		fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
		fl.Flush()
		ping := time.NewTicker(20 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-a.quit:
				return
			case m := <-ch:
				w.Write(m)
				fl.Flush()
			case <-ping.C:
				fmt.Fprint(w, ": ping\n\n")
				fl.Flush()
			}
		}
	})

	api("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		req.Host = strings.TrimSpace(req.Host)
		if !reHost.MatchString(req.Host) {
			writeErr(w, "Ungültige Router-Adresse")
			return
		}
		if req.Port <= 0 || req.Port > 65535 {
			req.Port = 22
		}
		if req.User == "" {
			req.User = "root"
		}
		cur := a.store.Get()
		if cur.RouterHost != req.Host || cur.RouterPort != req.Port {
			a.router.Forget()
		}
		_ = a.store.Update(func(c *Config) { c.RouterHost, c.RouterPort, c.RouterUser = req.Host, req.Port, req.User })
		var err error
		if req.Password != "" {
			err = a.router.ConnectPassword(req.Password)
		} else {
			err = a.router.ConnectKey()
		}
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.State())
	})

	api("/api/forget", func(w http.ResponseWriter, r *http.Request) {
		a.stopAllMonitors()
		a.router.Forget()
		a.pushState()
		writeJSON(w, a.State())
	})

	api("/api/live/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if err := a.startMonitor(req.Host, true); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.State())
	})
	api("/api/live/stop", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		a.stopMonitor(req.Host)
		writeJSON(w, a.State())
	})

	api("/api/scan/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Countries []string `json:"countries"`
			Pings     int      `json:"pings"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		var cc []string
		for _, c := range req.Countries {
			c = strings.ToLower(strings.TrimSpace(c))
			if len(c) >= 2 && len(c) <= 3 {
				cc = append(cc, c)
			}
		}
		if ok, _, _ := a.router.State(); !ok {
			writeErr(w, "Nicht mit dem Router verbunden")
			return
		}
		if err := a.scanner.Start(cc, req.Pings); err != nil {
			writeErr(w, err.Error())
			return
		}
		_ = a.store.Update(func(c *Config) { c.Countries, c.ScanPings = cc, req.Pings })
		writeJSON(w, a.scanner.State())
	})
	api("/api/scan/stop", func(w http.ResponseWriter, r *http.Request) {
		a.scanner.Stop()
		writeJSON(w, a.scanner.State())
	})

	api("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			LogCSV *bool `json:"log_csv"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.LogCSV != nil {
			_ = a.store.Update(func(c *Config) { c.LogCSV = *req.LogCSV })
		}
		a.pushState()
		writeJSON(w, a.State())
	})

	api("/api/relays/refresh", func(w http.ResponseWriter, r *http.Request) {
		if err := a.relays.Load(true); err != nil {
			writeErr(w, err.Error())
			return
		}
		a.mu.Lock()
		a.relayErr = ""
		a.mu.Unlock()
		a.router.Refresh()
		writeJSON(w, a.State())
	})

	api("/api/open-data", func(w http.ResponseWriter, r *http.Request) {
		d := a.csv.dir()
		_ = os.MkdirAll(d, 0o755)
		if runtime.GOOS == "windows" {
			exec.Command("explorer", d).Start()
		} else {
			exec.Command("xdg-open", d).Start()
		}
		writeJSON(w, map[string]string{"dir": d})
	})

	api("/api/quit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); close(a.quit) }()
	})
	return a.guardHost(mux)
}

// Schutz gegen DNS-Rebinding: nur Aufrufe an 127.0.0.1/localhost annehmen.
func (a *App) guardHost(h http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(a.addr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1:"+port && r.Host != "localhost:"+port {
			http.Error(w, "falscher Host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie("mlat")
	return err == nil && c.Value == a.token
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		writeErr(w, "Ungültige Anfrage")
		return false
	}
	return true
}

var _ = strconv.Itoa

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	static := http.FileServer(http.FS(sub))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if k := r.URL.Query().Get("k"); k != "" {
			if k == a.token {
				http.SetCookie(w, &http.Cookie{Name: "relayping", Value: a.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 400 * 24 * 3600})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
		if !a.authed(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>RelayPing</title><body style="font-family:system-ui;background:#0e1116;color:#e6ebf5;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center;max-width:520px;padding:20px"><h2>RelayPing</h2><p>Bitte über das RelayPing-Symbol in der Taskleiste („Öffnen“) oder die RelayPing.exe öffnen.</p><p style="color:#8a8f9a">Please open via the RelayPing tray icon (“Open”) or RelayPing.exe.</p></div>`)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, r)
	})

	api := func(path string, h func(w http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if !a.authed(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if r.Method != http.MethodGet && r.Header.Get("X-RelayPing") != "1" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h(w, r)
		})
	}
	ok := func(w http.ResponseWriter) { writeJSON(w, a.State()) }

	api("/api/state", func(w http.ResponseWriter, r *http.Request) { ok(w) })
	api("/api/relays", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.relays.All()) })
	api("/api/scan", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.scanner.State()) })
	api("/api/board", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.board.State()) })
	api("/api/alerts", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.alerts.List()) })
	api("/api/switch", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.switcher.Status()) })
	api("/api/speed", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.speed.State()) })
	api("/api/geo", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.geo.State()) })
	api("/api/geo/compare", func(w http.ResponseWriter, r *http.Request) {
		if err := a.geo.Compare(); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.geo.State())
	})
	api("/api/blockcheck/list", func(w http.ResponseWriter, r *http.Request) {
		t, list, err := a.geo.DomainList(0)
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, map[string]any{"tunnel_id": t.TunnelID, "name": t.Name, "iface": t.Iface, "host": t.Host, "domains": list})
	})
	api("/api/blockcheck", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domains []string `json:"domains"`
			Iface   string   `json:"iface"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		var list []string
		if _, l, err := a.geo.DomainList(0); err == nil {
			list = l
		}
		res, dns, err := a.geo.BlockCheck(req.Domains, req.Iface, list)
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, map[string]any{"results": res, "dns": dns})
	})
	api("/api/report", func(w http.ResponseWriter, r *http.Request) {
		a.day.writeReport()
		writeJSON(w, a.day.Build(time.Now()))
	})
	api("/api/speed/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Iface string `json:"iface"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		if err := a.speed.Start(req.Iface); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.speed.State())
	})

	api("/api/events", func(w http.ResponseWriter, r *http.Request) {
		fl, isFl := w.(http.Flusher)
		if !isFl {
			http.Error(w, "no streaming", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		ch := make(chan []byte, 512)
		a.mu.Lock()
		a.clients[ch] = true
		a.mu.Unlock()
		defer func() { a.mu.Lock(); delete(a.clients, ch); a.mu.Unlock() }()
		for _, ev := range []struct {
			name string
			v    any
		}{{"state", a.State()}, {"backfill", a.backfill()}, {"board", a.board.State()}, {"alerts", a.alerts.List()}, {"switch", a.switcher.Status()}, {"speed", a.speed.State()}, {"geo", a.geo.State()}} {
			b, _ := json.Marshal(ev.v)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.name, b)
		}
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
		if !a.readJSON(w, r, &req) {
			return
		}
		req.Host = strings.TrimSpace(req.Host)
		if !reHost.MatchString(req.Host) {
			writeErr(w, a.tr("Ungültige Router-Adresse", "Invalid router address"))
			return
		}
		if req.Port <= 0 || req.Port > 65535 {
			req.Port = 22
		}
		if req.User == "" || !reIface.MatchString(req.User) {
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
		ok(w)
	})

	api("/api/forget", func(w http.ResponseWriter, r *http.Request) {
		a.stopAllMonitors()
		a.router.Forget()
		a.pushState()
		ok(w)
	})

	hostReq := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		var req struct {
			Host string `json:"host"`
		}
		if !a.readJSON(w, r, &req) {
			return "", false
		}
		return req.Host, true
	}
	api("/api/live/start", func(w http.ResponseWriter, r *http.Request) {
		h, good := hostReq(w, r)
		if !good {
			return
		}
		if err := a.startMonitor(h, true); err != nil {
			writeErr(w, err.Error())
			return
		}
		ok(w)
	})
	api("/api/live/stop", func(w http.ResponseWriter, r *http.Request) {
		h, good := hostReq(w, r)
		if !good {
			return
		}
		a.stopMonitor(h)
		ok(w)
	})

	cleanCC := func(in []string) []string {
		var cc []string
		seen := map[string]bool{}
		for _, c := range in {
			c = strings.ToLower(strings.TrimSpace(c))
			if len(c) >= 2 && len(c) <= 3 && !seen[c] {
				seen[c] = true
				cc = append(cc, c)
			}
		}
		return cc
	}

	api("/api/scan/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Countries []string `json:"countries"`
			Pings     int      `json:"pings"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		cc := cleanCC(req.Countries)
		if c, _, _ := a.router.State(); !c {
			writeErr(w, a.tr("Nicht mit dem Router verbunden", "Not connected to the router"))
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

	api("/api/switch/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TunnelID     int    `json:"tunnel_id"`
			Host         string `json:"host"`
			AllowCountry bool   `json:"allow_country"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		if err := a.switcher.Start(req.TunnelID, req.Host, req.AllowCountry); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.switcher.Status())
	})

	api("/api/alerts/dismiss", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID int64 `json:"id"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		a.alerts.Dismiss(req.ID)
		writeJSON(w, a.alerts.List())
	})

	api("/api/favorites/save", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name  string   `json:"name"`
			Hosts []string `json:"hosts"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		if err := a.saveFavorite(req.Name, req.Hosts); err != nil {
			writeErr(w, err.Error())
			return
		}
		a.pushState()
		ok(w)
	})
	api("/api/favorites/delete", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		_ = a.store.Update(func(c *Config) { delete(c.Favorites, req.Name) })
		a.pushState()
		ok(w)
	})
	api("/api/favorites/apply", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		if err := a.applyFavorite(req.Name); err != nil {
			writeErr(w, err.Error())
			return
		}
		ok(w)
	})

	api("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			LogCSV      *bool    `json:"log_csv"`
			Lang        *string  `json:"lang"`
			Alerts      *bool    `json:"alerts"`
			AlertLoss   *int     `json:"alert_loss"`
			AlertExtra  *float64 `json:"alert_extra_ms"`
			AutoScanMin *int     `json:"auto_scan_min"`
			BoardOn     *bool    `json:"board_on"`
			BoardCC     []string `json:"board_countries"`
			BoardSec    *int     `json:"board_interval"`
			ChartScale  *string  `json:"chart_scale"`
			Autostart   *bool    `json:"autostart"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		restartBoard := req.BoardOn != nil || req.BoardCC != nil || req.BoardSec != nil
		_ = a.store.Update(func(c *Config) {
			if req.LogCSV != nil {
				c.LogCSV = *req.LogCSV
			}
			if req.Lang != nil {
				c.Lang = *req.Lang
			}
			if req.Alerts != nil {
				c.Alerts = *req.Alerts
			}
			if req.AlertLoss != nil {
				c.AlertLossPct = *req.AlertLoss
			}
			if req.AlertExtra != nil {
				c.AlertExtraMs = *req.AlertExtra
			}
			if req.AutoScanMin != nil {
				c.AutoScanMin = *req.AutoScanMin
			}
			if req.BoardOn != nil {
				c.BoardOn = *req.BoardOn
			}
			if req.BoardCC != nil {
				if cc := cleanCC(req.BoardCC); len(cc) > 0 {
					c.BoardCountries = cc
				}
			}
			if req.BoardSec != nil {
				c.BoardInterval = *req.BoardSec
			}
			if req.ChartScale != nil {
				c.ChartScale = *req.ChartScale
			}
		})
		if req.Autostart != nil {
			if err := setAutostart(*req.Autostart); err != nil {
				writeErr(w, err.Error())
				return
			}
		}
		if req.Lang != nil {
			a.tray.SetLang(a.store.Get().Lang)
		}
		if restartBoard {
			a.board.Restart()
			a.broadcast("board", a.board.State())
		}
		a.pushState()
		ok(w)
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
		a.board.Restart()
		ok(w)
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
		go func() { time.Sleep(200 * time.Millisecond); a.Quit() }()
	})
	return a.guardHost(mux)
}

// Schutz gegen DNS-Rebinding: nur Aufrufe an 127.0.0.1/localhost annehmen.
func (a *App) guardHost(h http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(a.addr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1:"+port && r.Host != "localhost:"+port {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie("relayping")
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

func (a *App) readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		writeErr(w, a.tr("Ungültige Anfrage", "Invalid request"))
		return false
	}
	return true
}

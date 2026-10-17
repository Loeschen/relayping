package main

import (
	"net/http"
	"strings"
)

// Routen für DNS-Wächter, Ping nach Uhrzeit, Handy-Meldungen, Handy-Ansicht und PC-Modus.
func (a *App) extraRoutes(api func(string, func(http.ResponseWriter, *http.Request))) {
	api("/api/dns", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.dnsw.Stats()) })
	api("/api/dns/check", func(w http.ResponseWriter, r *http.Request) {
		a.dnsw.Check()
		writeJSON(w, a.dnsw.Stats())
	})
	api("/api/dns/settings", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Interval int    `json:"interval"`
			Server   string `json:"server"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		srv := strings.TrimSpace(req.Server)
		if srv != "" && !reHost.MatchString(srv) {
			writeErr(w, a.tr("Ungültige DNS-Adresse", "Invalid DNS address"))
			return
		}
		if req.Interval < 0 || req.Interval > 3600 {
			writeErr(w, a.tr("Ungültiger Abstand", "Invalid interval"))
			return
		}
		_ = a.store.Update(func(c *Config) { c.DNSWatchSec, c.DNSWatchServer = req.Interval, srv })
		if req.Interval > 0 {
			a.dnsw.Wake()
		}
		a.broadcast("dns", a.dnsw.Stats())
		writeJSON(w, a.dnsw.Stats())
	})
	api("/api/heat", func(w http.ResponseWriter, r *http.Request) {
		days := 28
		if r.URL.Query().Get("days") == "7" {
			days = 7
		}
		writeJSON(w, a.Heat(days))
	})
	api("/api/push", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.pusher.State()) })
	api("/api/push/settings", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mode    string          `json:"mode"`
			Ntfy    string          `json:"ntfy"`
			TgToken string          `json:"tg_token"`
			TgChat  string          `json:"tg_chat"`
			Cats    map[string]bool `json:"cats"`
			Keep    bool            `json:"keep"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		if err := a.pusher.Configure(req.Mode, req.Ntfy, req.TgToken, req.TgChat, req.Cats, req.Keep); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.pusher.State())
	})
	api("/api/push/test", func(w http.ResponseWriter, r *http.Request) {
		if err := a.pusher.Test(); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.pusher.State())
	})
	api("/api/lan/info", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.lan.Info()) })
	api("/api/lan/settings", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			On     bool `json:"on"`
			Port   int  `json:"port"`
			NewKey bool `json:"new_key"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		if err := a.lan.Configure(req.On, req.Port, req.NewKey); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.lan.Info())
	})
	api("/api/localmode", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			On bool `json:"on"`
		}
		if !a.readJSON(w, r, &req) {
			return
		}
		if err := a.SetLocalMode(req.On); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, a.State())
	})
}

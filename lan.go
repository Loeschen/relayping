package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Handy-Ansicht im Heimnetz: Auf Wunsch lauscht RelayPing zusätzlich auf der
// Heimnetz-Adresse des PCs. Zugang nur mit eigenem Schlüssel (im QR-Code), der sich
// jederzeit neu erzeugen lässt. Über diesen Weg sind Einstellungen, Beenden und
// Router-Zugang gesperrt – das Handy kann ansehen, messen und Server wechseln.

type ctxKey int

const lanCtx ctxKey = 1

// Aktionen, die vom Handy aus nicht erlaubt sind.
var lanBlocked = map[string]bool{
	"/api/quit": true, "/api/settings": true, "/api/connect": true, "/api/forget": true,
	"/api/fritz/settings": true, "/api/update/apply": true, "/api/push": true, "/api/push/settings": true, "/api/push/test": true,
	"/api/lan/settings": true, "/api/lan/info": true, "/api/lan/newkey": true, "/api/open-data": true,
	"/api/localmode": true, "/api/dns/settings": true,
}

func isLAN(r *http.Request) bool { return r.Context().Value(lanCtx) != nil }

type LANServer struct {
	app  *App
	mu   sync.Mutex
	srv  *http.Server
	addr string
	err  string
}

type LANInfo struct {
	On    bool   `json:"on"`
	Addr  string `json:"addr,omitempty"`
	URL   string `json:"url,omitempty"`
	Port  int    `json:"port"`
	Error string `json:"error,omitempty"`
}

// localIP: die Adresse des PCs, über die er den Router erreicht.
func (l *LANServer) localIP() (net.IP, error) {
	if ip := net.ParseIP(envOr("RELAYPING_LAN_IP", "")); ip != nil { // nur für Tests
		return ip, nil
	}
	target := l.app.store.Get().RouterHost
	if net.ParseIP(target) == nil {
		target = "192.168.8.1"
	}
	c, err := net.Dial("udp", net.JoinHostPort(target, "53")) // es wird nichts gesendet
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if ip.IsLoopback() || !ip.IsPrivate() {
		return nil, errors.New("keine Heimnetz-Adresse gefunden")
	}
	return ip, nil
}

func newLANToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Apply startet oder stoppt den Heimnetz-Zugang passend zur Einstellung.
func (l *LANServer) Apply() {
	a := l.app
	c := a.store.Get()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = l.srv.Shutdown(ctx)
		cancel()
		l.srv, l.addr = nil, ""
	}
	l.err = ""
	if !c.LANOn || c.LANToken == "" {
		return
	}
	ip, err := l.localIP()
	if err != nil {
		l.err = err.Error()
		return
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(c.LANPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		l.err = fmt.Sprintf(a.tr("Port %d ist belegt oder gesperrt (%v)", "Port %d is in use or blocked (%v)"), c.LANPort, err)
		return
	}
	l.addr = addr
	l.srv = &http.Server{Handler: l.guard(a.mux()), ReadHeaderTimeout: 10 * time.Second}
	go l.srv.Serve(ln)
	a.log.Printf("Handy-Ansicht im Heimnetz unter %s eingeschaltet", addr)
}

func (l *LANServer) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		addr := l.addr
		l.mu.Unlock()
		if r.Host != addr {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		if lanBlocked[r.URL.Path] {
			http.Error(w, "nur am PC", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), lanCtx, true)))
	})
}

func (l *LANServer) Info() LANInfo {
	c := l.app.store.Get()
	l.mu.Lock()
	defer l.mu.Unlock()
	in := LANInfo{On: c.LANOn, Port: c.LANPort, Error: l.err}
	if l.addr != "" {
		in.Addr = l.addr
		in.URL = "http://" + l.addr + "/?k=" + c.LANToken
	}
	return in
}

func (l *LANServer) Configure(on bool, port int, newKey bool) error {
	a := l.app
	if port != 0 && (port < 1024 || port > 65535) {
		return errors.New(a.tr("Port zwischen 1024 und 65535 wählen", "Choose a port between 1024 and 65535"))
	}
	err := a.store.Update(func(c *Config) {
		c.LANOn = on
		if port != 0 {
			c.LANPort = port
		}
		if newKey || c.LANToken == "" {
			c.LANToken = newLANToken()
		}
	})
	if err != nil {
		return err
	}
	l.Apply()
	return nil
}

// lanToken liefert den Handy-Schlüssel (leer, wenn aus).
func (a *App) lanToken() string {
	c := a.store.Get()
	if !c.LANOn {
		return ""
	}
	return strings.TrimSpace(c.LANToken)
}

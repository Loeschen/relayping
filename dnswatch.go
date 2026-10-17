package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// DNS-Wächter: fragt regelmäßig Namen ab – einmal über den DNS-Server des Routers
// (bei GL.iNet meist AdGuard Home) und zum Vergleich direkt beim Mullvad-DNS im
// Tunnel (10.64.0.1). So zeigt sich, ob Hänger wie „Server failed“ oder fehlende
// IPv4-Antworten am Router entstehen oder bei Mullvad. Es wird nur gefragt, nichts
// eingestellt.

const dnsMullvad = "10.64.0.1"

var dnsNames = []string{
	"www.tagesschau.de", "www.wikipedia.org", "www.ebay.de", "www.zdf.de", "store.steampowered.com",
	"github.com", "www.amazon.de", "www.spiegel.de", "www.youtube.com", "www.twitch.tv",
	"www.bahn.de", "www.dhl.de", "www.heise.de", "www.idealo.de", "www.ikea.com",
	"www.otto.de", "www.reddit.com", "www.netflix.com", "www.t-online.de", "www.chip.de",
}

type DNSRes struct {
	Code  string  `json:"code"` // ok, langsam, servfail, nxdomain, keine-ipv4, timeout, fehler, aus
	Ms    float64 `json:"ms"`
	Addrs int     `json:"addrs"`
}

type DNSCheck struct {
	T      int64  `json:"t"`
	Name   string `json:"name"`
	Random bool   `json:"zufall,omitempty"` // Name gibt es nicht (Cache umgehen): NXDOMAIN ist richtig
	Router DNSRes `json:"router"`
	Direct DNSRes `json:"direkt"`
}

type DNSStats struct {
	Interval  int        `json:"interval"`
	Server    string     `json:"server"`
	Checks    int        `json:"checks"`
	RouterBad int        `json:"router_bad"`
	DirectBad int        `json:"direct_bad"`
	RouterMed float64    `json:"router_med"`
	DirectMed float64    `json:"direct_med"`
	DirectOK  bool       `json:"direct_ok"` // Mullvad-DNS überhaupt erreichbar
	Recent    []DNSCheck `json:"recent"`    // die letzten 60
	Problems  []DNSCheck `json:"problems"`  // Probleme der letzten 24 h (neueste zuerst, max. 30)
	Running   bool       `json:"running"`
}

type DNSWatch struct {
	app    *App
	mu     sync.Mutex
	file   string
	checks []DNSCheck
	idx    int
	wake   chan struct{}
	busy   bool
	saved  time.Time
}

func newDNSWatch(a *App, file string) *DNSWatch {
	d := &DNSWatch{app: a, file: file, wake: make(chan struct{}, 1)}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &d.checks)
	}
	return d
}

// ---------- DNS-Abfrage (eigene, damit RCODE und Antwortzahl sichtbar sind) ----------

func buildDNSQuery(id uint16, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return nil, errors.New("ungültiger Name")
	}
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)      // eine Frage
	for _, l := range strings.Split(name, ".") {
		if len(l) == 0 || len(l) > 63 {
			return nil, errors.New("ungültiger Name")
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1) // Ende, Typ A, Klasse IN
	return b, nil
}

// skipName überspringt einen (ggf. komprimierten) Namen ab off.
func skipName(m []byte, off int) (int, error) {
	for i := 0; i < 128; i++ {
		if off >= len(m) {
			return 0, errors.New("kurz")
		}
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
	return 0, errors.New("Schleife")
}

// parseDNSReply liefert RCODE und die Zahl der A-Einträge.
func parseDNSReply(m []byte, id uint16) (rcode, nA int, err error) {
	if len(m) < 12 || binary.BigEndian.Uint16(m[0:]) != id {
		return 0, 0, errors.New("fremde Antwort")
	}
	flags := binary.BigEndian.Uint16(m[2:])
	rcode = int(flags & 0x0F)
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		if off, err = skipName(m, off); err != nil {
			return rcode, 0, err
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if off, err = skipName(m, off); err != nil {
			return rcode, nA, nil
		}
		if off+10 > len(m) {
			return rcode, nA, nil
		}
		typ := binary.BigEndian.Uint16(m[off:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		if typ == 1 && rdlen == 4 {
			nA++
		}
		off += 10 + rdlen
	}
	return rcode, nA, nil
}

func dnsQuery(server, name string, timeout time.Duration) DNSRes {
	return dnsQueryAddr(net.JoinHostPort(server, "53"), name, timeout)
}

func dnsQueryAddr(addr, name string, timeout time.Duration) DNSRes {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := buildDNSQuery(id, name)
	if err != nil {
		return DNSRes{Code: "fehler"}
	}
	start := time.Now()
	c, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return DNSRes{Code: "fehler"}
	}
	defer c.Close()
	_ = c.SetDeadline(start.Add(timeout))
	if _, err := c.Write(q); err != nil {
		return DNSRes{Code: "fehler"}
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		ms := round1(float64(time.Since(start).Microseconds()) / 1000)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return DNSRes{Code: "timeout", Ms: ms}
			}
			return DNSRes{Code: "fehler", Ms: ms}
		}
		rc, nA, perr := parseDNSReply(buf[:n], id)
		if perr != nil && perr.Error() == "fremde Antwort" {
			continue
		}
		r := DNSRes{Ms: ms, Addrs: nA}
		switch {
		case rc == 2:
			r.Code = "servfail"
		case rc == 3:
			r.Code = "nxdomain"
		case rc != 0:
			r.Code = "fehler"
		case nA == 0:
			r.Code = "keine-ipv4"
		case ms > 2500:
			r.Code = "langsam"
		default:
			r.Code = "ok"
		}
		return r
	}
}

// bad: ist das Ergebnis ein Problem? Bei Zufallsnamen ist „gibt es nicht“ die richtige Antwort.
func (r DNSRes) bad(random bool) bool {
	switch r.Code {
	case "ok", "aus", "":
		return false
	case "nxdomain":
		return !random
	case "langsam":
		return true
	}
	return true
}

// ---------- Ablauf ----------

func (d *DNSWatch) server() string {
	c := d.app.store.Get()
	h := c.RouterHost
	if c.DNSWatchServer != "" {
		h = c.DNSWatchServer
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	if ips, err := net.LookupIP(h); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func (d *DNSWatch) Wake() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *DNSWatch) Run() {
	last := time.Time{}
	for !d.app.quitting() {
		iv := d.app.store.Get().DNSWatchSec
		select {
		case <-d.app.quit:
			d.save()
			return
		case <-d.wake:
			d.Check()
			last = time.Now()
			continue
		case <-time.After(2 * time.Second):
		}
		if iv > 0 && time.Since(last) >= time.Duration(iv)*time.Second {
			d.Check()
			last = time.Now()
		}
	}
}

// Check fragt einen echten und einen erfundenen Namen ab (der erfundene geht immer am Zwischenspeicher vorbei).
func (d *DNSWatch) Check() {
	srv := d.server()
	if srv == "" {
		return
	}
	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		return
	}
	d.busy = true
	name := dnsNames[d.idx%len(dnsNames)]
	d.idx++
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.busy = false; d.mu.Unlock() }()
	rb := make([]byte, 5)
	_, _ = rand.Read(rb)
	fake := "rp-" + hex.EncodeToString(rb) + ".example.com"
	var out []DNSCheck
	for _, q := range []struct {
		n    string
		rand bool
	}{{name, false}, {fake, true}} {
		c := DNSCheck{T: time.Now().Unix(), Name: q.n, Random: q.rand}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); c.Router = dnsQuery(srv, q.n, 12*time.Second) }()
		go func() { defer wg.Done(); c.Direct = dnsQuery(dnsMullvad, q.n, 12*time.Second) }()
		wg.Wait()
		out = append(out, c)
	}
	d.mu.Lock()
	d.checks = append(d.checks, out...)
	cut := time.Now().Add(-24 * time.Hour).Unix()
	i := 0
	for i < len(d.checks) && d.checks[i].T < cut {
		i++
	}
	d.checks = d.checks[i:]
	save := time.Since(d.saved) > 10*time.Minute
	d.mu.Unlock()
	if save {
		d.save()
	}
	for _, c := range out {
		d.judge(c)
	}
	d.app.broadcast("dns", d.Stats())
}

// judge trägt Probleme als Kurzaussetzer „DNS“ ins Protokoll ein.
func (d *DNSWatch) judge(c DNSCheck) {
	a := d.app
	rBad, dBad := c.Router.bad(c.Random), c.Direct.bad(c.Random)
	if !rBad {
		return
	}
	target := a.tr("Router-DNS", "router DNS")
	// Mullvad nur dann verantwortlich machen, wenn es sonst direkt erreichbar ist
	if dBad && d.directSeen() {
		target = "Mullvad-DNS"
	}
	dur := int64(c.Router.Ms/1000 + 0.5)
	if dur < 1 {
		dur = 1
	}
	merged := a.outages.AddBlip("kurz-dns", target, c.T, c.T+dur)
	msg := fmt.Sprintf(a.tr("DNS-Problem bei %s: %s nach %s (%s)", "DNS problem at %s: %s after %s (%s)"),
		target, dnsCodeText(a, c.Router.Code), durText(a, dur), c.Name)
	a.day.Event("ausfall", msg)
	if merged {
		a.log.Printf("DNS-Wächter (zusammengefasst): %s", msg)
		return
	}
	a.notify(a.tr("RelayPing: DNS", "RelayPing: DNS"), msg)
	a.push("dns", a.tr("DNS-Problem", "DNS problem"), msg)
}

func (d *DNSWatch) directSeen() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := len(d.checks) - 1; i >= 0 && i >= len(d.checks)-200; i-- {
		if c := d.checks[i]; !c.Random && c.Direct.Code == "ok" {
			return true
		}
	}
	return false
}

func dnsCodeText(a *App, code string) string {
	switch code {
	case "servfail":
		return a.tr("„Server failed“", "“server failed”")
	case "nxdomain":
		return a.tr("„gibt es nicht“", "“does not exist”")
	case "keine-ipv4":
		return a.tr("keine IPv4-Adresse", "no IPv4 address")
	case "timeout":
		return a.tr("keine Antwort", "no answer")
	case "langsam":
		return a.tr("sehr langsam", "very slow")
	}
	return a.tr("Fehler", "error")
}

func (d *DNSWatch) save() {
	d.mu.Lock()
	b, err := json.Marshal(d.checks)
	d.saved = time.Now()
	d.mu.Unlock()
	if err == nil {
		writeAtomic(d.file, b)
	}
}

func (d *DNSWatch) Stats() DNSStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := DNSStats{Interval: d.app.store.Get().DNSWatchSec, Running: d.busy}
	st.Server = d.server()
	var rm, dm []float64
	for _, c := range d.checks {
		st.Checks++
		if c.Router.bad(c.Random) {
			st.RouterBad++
		} else if c.Router.Code != "" {
			rm = append(rm, c.Router.Ms)
		}
		if c.Direct.bad(c.Random) {
			st.DirectBad++
		} else if c.Direct.Code != "" {
			dm = append(dm, c.Direct.Ms)
		}
		if !c.Random && c.Direct.Code == "ok" {
			st.DirectOK = true
		}
	}
	st.RouterMed, st.DirectMed = round1(median(rm)), round1(median(dm))
	n := len(d.checks)
	st.Recent = append([]DNSCheck{}, d.checks[max(0, n-60):]...)
	for i := n - 1; i >= 0 && len(st.Problems) < 30; i-- {
		c := d.checks[i]
		if c.Router.bad(c.Random) || c.Direct.bad(c.Random) {
			st.Problems = append(st.Problems, c)
		}
	}
	if st.Problems == nil {
		st.Problems = []DNSCheck{}
	}
	return st
}

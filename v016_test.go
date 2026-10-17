package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeDNS antwortet je nach Name: ok.* mit zwei A-Einträgen, fail.* mit SERVFAIL,
// v6.* ohne A-Eintrag, slow.* gar nicht.
func fakeDNS(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			name := ""
			for off := 12; off < len(q) && q[off] != 0; {
				l := int(q[off])
				name += string(q[off+1:off+1+l]) + "."
				off += 1 + l
			}
			resp := append([]byte(nil), q...)
			binary.BigEndian.PutUint16(resp[2:], 0x8180)
			switch {
			case strings.HasPrefix(name, "slow."):
				continue
			case strings.HasPrefix(name, "fail."):
				binary.BigEndian.PutUint16(resp[2:], 0x8182)
			case strings.HasPrefix(name, "v6."):
			case strings.HasPrefix(name, "ok."):
				binary.BigEndian.PutUint16(resp[6:], 2)
				for i := 0; i < 2; i++ {
					resp = append(resp, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, byte(4+i))
				}
			}
			pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDNSQuery(t *testing.T) {
	addr := fakeDNS(t)
	for name, want := range map[string]string{"ok.example": "ok", "fail.example": "servfail", "v6.example": "keine-ipv4", "slow.example": "timeout"} {
		r := dnsQueryAddr(addr, name, 400*time.Millisecond)
		if r.Code != want {
			t.Fatalf("%s: %+v, erwartet %s", name, r, want)
		}
	}
	if r := dnsQueryAddr(addr, "ok.example", time.Second); r.Addrs != 2 {
		t.Fatalf("A-Einträge: %+v", r)
	}
	if (DNSRes{Code: "nxdomain"}).bad(true) || !(DNSRes{Code: "nxdomain"}).bad(false) || !(DNSRes{Code: "keine-ipv4"}).bad(false) {
		t.Fatal("Bewertung falsch")
	}
}

func TestHeat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "live.csv")
	var b strings.Builder
	b.WriteString("\xef\xbb\xbfZeitpunkt;Server;Stadt;Gesendet;Empfangen;Verlust %;Mittel ms;Min ms;Max ms;Jitter ms\r\n")
	now := time.Date(2026, 10, 16, 23, 0, 0, 0, time.Local) // Freitag
	for i := 0; i < 600; i++ {
		ts := now.Add(-time.Duration(i) * time.Minute)
		ms := "11,5"
		recv := 60
		if ts.Hour() >= 21 {
			ms, recv = "15,0", 57
		}
		b.WriteString(ts.Format("02.01.2006 15:04") + ";de-dus-wg-102;Dusseldorf;60;" + itoa(recv) + ";0;" + ms + ";11,0;12,0;0,3\r\n")
	}
	b.WriteString("01.01.2020 10:00;alt;X;60;60;0;9,0;9;9;0\r\n")
	os.WriteFile(p, []byte(b.String()), 0o644)
	h := buildHeat(p, 28, now)
	if len(h.Servers) != 1 {
		t.Fatalf("%+v", h)
	}
	s := h.Servers[0]
	c := s.Grid[4][21]
	if c == nil || c.Ms != 15 || c.Loss != 5 || s.Min != 11.5 || s.Max != 15 || !strings.HasPrefix(s.Worst, "Fr 2") {
		t.Fatalf("%+v %+v", c, s)
	}
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+i/10)) + string(rune('0'+i%10)))
}

func TestPushConfigure(t *testing.T) {
	a := newTestApp(t)
	a.pusher = newPusher(a)
	if err := a.pusher.Configure("ntfy", "ntfy.sh/x", "", "", nil, false); err == nil {
		t.Fatal("ungültige Adresse angenommen")
	}
	if err := a.pusher.Configure("ntfy", "https://ntfy.sh/relayping-abc123", "", "", map[string]bool{"ausfall": true, "quatsch": true}, false); err != nil {
		t.Fatal(err)
	}
	c := a.store.Get()
	if c.PushMode != "ntfy" || strings.Contains(c.PushSecret, "ntfy.sh") || !c.PushCats["ausfall"] || c.PushCats["quatsch"] {
		t.Fatalf("%+v", c)
	}
	if st := a.pusher.State(); st.Target != "https://ntfy.sh/relayping-abc123" {
		t.Fatalf("%+v", st)
	}
	// Telegram: falsches Token
	if err := a.pusher.Configure("telegram", "", "123", "456", nil, false); err == nil {
		t.Fatal("ungültiges Token angenommen")
	}
	// Aus: Zugangsdaten weg
	if err := a.pusher.Configure("", "", "", "", nil, false); err != nil || a.store.Get().PushSecret != "" {
		t.Fatal("nicht gelöscht")
	}
}

func TestLANGuard(t *testing.T) {
	a := newTestApp(t)
	a.token = "pc-token"
	_ = a.store.Update(func(c *Config) { c.LANOn, c.LANToken = true, "handy-token" })
	l := &LANServer{app: a, addr: "192.168.8.20:47322"}
	h := l.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			http.Error(w, "forbidden", 403)
			return
		}
		io.WriteString(w, "ok")
	}))
	do := func(path, host, cookie string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "relayping", Value: cookie})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do("/api/state", "192.168.8.20:47322", "handy-token"); c != 200 {
		t.Fatalf("Handy-Schlüssel abgelehnt: %d", c)
	}
	if c := do("/api/state", "192.168.8.20:47322", "pc-token"); c != 403 {
		t.Fatalf("PC-Schlüssel im Heimnetz angenommen: %d", c)
	}
	if c := do("/api/quit", "192.168.8.20:47322", "handy-token"); c != 403 {
		t.Fatalf("Beenden vom Handy erlaubt: %d", c)
	}
	if c := do("/api/state", "evil.example:47322", "handy-token"); c != 403 {
		t.Fatalf("fremder Host angenommen: %d", c)
	}
	_ = a.store.Update(func(c *Config) { c.LANOn = false })
	if c := do("/api/state", "192.168.8.20:47322", "handy-token"); c != 403 {
		t.Fatalf("ausgeschaltet, aber Zugang: %d", c)
	}
}

func TestLocalScanStream(t *testing.T) {
	if _, err := os.Stat("/usr/sbin/ping"); err != nil {
		t.Skip("kein ping")
	}
	stop := make(chan struct{})
	r := localScanStream([]string{"10.1.1.1", "10.2.1.1"}, 3, stop)
	b, _ := io.ReadAll(r)
	out := string(b)
	if strings.Count(out, "\nR ")+strings.Count(out[:2], "R ") != 2 || !strings.HasSuffix(strings.TrimSpace(out), "DONE") {
		t.Fatalf("%q", out)
	}
}

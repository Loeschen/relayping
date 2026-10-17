package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func newTestApp(t *testing.T) *App {
	dir := t.TempDir()
	a := &App{quit: make(chan struct{}), clients: map[chan []byte]bool{}}
	a.store = loadStore(dir)
	a.log = newLogger(filepath.Join(dir, "log.txt"))
	a.tray = noTray{}
	a.day = newDay(a, filepath.Join(dir, "tag.json"))
	return a
}

func TestTrafficCounters(t *testing.T) {
	a := newTestApp(t)
	tr := newTraffic(a, filepath.Join(t.TempDir(), "v.json"))
	loc := time.Local
	t0 := time.Date(2026, 10, 3, 12, 0, 0, 0, loc)
	inf := RouterInfo{HaveWANCt: true, BootTime: 1000, WANRX: 5_000_000, WANTX: 1_000_000,
		Tunnels: []Tunnel{{Iface: "wg2", PubKey: "A", RX: 4_000_000, TX: 900_000}}}
	tr.Observe(inf, t0) // erster Lauf: nur Ausgangswert
	if st := tr.State(t0); st.Today.RX != 0 || st.Today.VPNRX != 0 {
		t.Fatalf("erster Lauf darf nichts zählen: %+v", st.Today)
	}
	inf.WANRX, inf.WANTX = 7_000_000, 1_500_000
	inf.Tunnels[0].RX, inf.Tunnels[0].TX = 5_500_000, 1_200_000
	tr.Observe(inf, t0.Add(10*time.Second))
	st := tr.State(t0.Add(10 * time.Second))
	if st.Today.RX != 2_000_000 || st.Today.TX != 500_000 || st.Today.VPNRX != 1_500_000 {
		t.Errorf("Zuwachs falsch: %+v", st.Today)
	}
	// Router-Neustart: Zähler beginnt bei 0, alles seit Neustart zählt
	inf.BootTime, inf.WANRX, inf.WANTX = 5000, 300_000, 100_000
	inf.Tunnels[0].RX, inf.Tunnels[0].TX = 200_000, 50_000
	tr.Observe(inf, t0.Add(20*time.Second))
	st = tr.State(t0.Add(20 * time.Second))
	if st.Today.RX != 2_300_000 || st.Gaps != 1 {
		t.Errorf("Neustart falsch: %+v gaps %d", st.Today, st.Gaps)
	}
	// Lücke über zwei Tage wird verteilt
	inf.WANRX = 300_000 + 48_000_000
	tr.Observe(inf, t0.Add(48*time.Hour+20*time.Second))
	st = tr.State(t0.Add(48*time.Hour + 20*time.Second))
	if len(st.Days) != 3 {
		t.Errorf("3 Tage erwartet, %d: %+v", len(st.Days), st.Days)
	}
	var sum uint64
	for _, d := range st.Days {
		sum += d.RX
	}
	if sum != 2_300_000+48_000_000 {
		t.Errorf("Summe %d", sum)
	}
}

func TestOutageDetect(t *testing.T) {
	a := newTestApp(t)
	o := newOutages(a, filepath.Join(t.TempDir(), "a.json"))
	a.outages = o
	now := time.Unix(1_800_000_000, 0)
	inf := RouterInfo{WANOK: 1, BootTime: 1_799_990_000, Tunnels: []Tunnel{{Iface: "wg2", Name: "Traffic", Host: "de-x", Probe: 1}}}
	o.Observe(true, inf, now)
	inf.Tunnels[0].Probe = 0
	for i := 1; i <= 3; i++ {
		o.Observe(true, inf, now.Add(time.Duration(i*10)*time.Second))
	}
	l := o.List()
	if len(l) != 1 || l[0].Kind != "tunnel" || l[0].End != 0 || l[0].Start != now.Unix()+10 {
		t.Fatalf("Tunnel-Ausfall erwartet: %+v", l)
	}
	inf.Tunnels[0].Probe = 1
	o.Observe(true, inf, now.Add(60*time.Second))
	if l = o.List(); l[0].End != now.Unix()+60 {
		t.Errorf("Ausfall nicht beendet: %+v", l)
	}
	// Internet weg: Tunnel-Fehler werden nicht zusätzlich gezählt
	inf.WANOK, inf.Tunnels[0].Probe = 0, 0
	for i := 7; i <= 10; i++ {
		o.Observe(true, inf, now.Add(time.Duration(i*10)*time.Second))
	}
	kinds := map[string]int{}
	for _, x := range o.List() {
		kinds[x.Kind]++
	}
	if kinds["internet"] != 1 {
		t.Errorf("Internet-Ausfall erwartet: %v", kinds)
	}
	// Neustart
	inf.WANOK, inf.BootTime = 1, 1_800_000_150
	o.Observe(true, inf, now.Add(200*time.Second))
	found := false
	for _, x := range o.List() {
		found = found || x.Kind == "neustart"
	}
	if !found {
		t.Errorf("Neustart nicht erkannt: %+v", o.List())
	}
}

func TestParseDevices(t *testing.T) {
	raw := json.RawMessage(`{"clients":[{"mac":"AA:BB","name":"PC","ip":"192.168.8.10","online":true,"total_rx":1000,"total_tx":200,"rx":50,"tx":5},
		{"mac":"CC:DD","alias":"Handy","ip":"192.168.8.11","online":false,"total_rx":"3000","total_tx":"100"}]}`)
	d, ok := parseDevices(raw)
	if !ok || len(d) != 2 || d[0].Name != "Handy" || d[0].RX != 3000 || d[1].RXRate != 50 || d[1].MAC != "aa:bb" {
		t.Errorf("Geräte falsch: %+v %v", d, ok)
	}
	if _, ok := parseDevices(json.RawMessage(`{"clients":[{"mac":"x","name":"y"}]}`)); ok {
		t.Error("ohne Zählerfelder darf has_traffic nicht true sein")
	}
}

func TestBufferGrade(t *testing.T) {
	idle := PingStats{N: 20, Median: 10}
	cases := map[float64]string{12: "A", 30: "B", 60: "C", 90: "D"}
	for load, want := range cases {
		if g := bufferGrade(idle, PingStats{N: 40, Median: load}, PingStats{N: 40, Median: 11}); g != want {
			t.Errorf("Last %v: %s, erwartet %s", load, g, want)
		}
	}
}

package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestParseConntrack(t *testing.T) {
	l := "ipv4     2 udp      17 177 src=192.168.8.100 dst=137.221.106.19 sport=55734 dport=3724 packets=1234 bytes=98765 src=137.221.106.19 dst=10.72.166.25 sport=3724 dport=55734 packets=2345 bytes=234567 [ASSURED] mark=0 zone=0 use=2"
	e, ok := parseConntrack(l)
	if !ok || e.proto != "udp" || e.src != "192.168.8.100" || e.dst != "137.221.106.19" || e.dport != 3724 || e.pkts != 1234 || e.rpkts != 2345 || e.rdst != "10.72.166.25" || !e.haveCounters {
		t.Fatalf("falsch: %+v", e)
	}
	l = "ipv4     2 tcp      6 7440 ESTABLISHED src=192.168.8.100 dst=1.2.3.4 sport=50000 dport=1119 src=1.2.3.4 dst=10.72.166.25 sport=1119 dport=50000 [ASSURED] mark=0 use=2"
	e, ok = parseConntrack(l)
	if !ok || e.proto != "tcp" || e.dport != 1119 || e.haveCounters {
		t.Fatalf("tcp falsch: %+v", e)
	}
	if guessGame("udp", 3724) == "" || guessGame("tcp", 443) != "" || !ignoredPort("udp", 443) {
		t.Error("Port-Zuordnung falsch")
	}
	if !privateIP("10.64.0.1") || privateIP("137.221.106.19") || !privateIP("100.64.1.1") {
		t.Error("privateIP falsch")
	}
}

func TestTickAndVersion(t *testing.T) {
	cases := map[float64]int{63.5: 64, 59: 60, 29: 30, 127: 128, 45: 0, 19.5: 20}
	for r, want := range cases {
		if got := nearestTick(r); got != want {
			t.Errorf("%v -> %d, erwartet %d", r, got, want)
		}
	}
	s := []GameSample{{In: 64}, {In: 63}, {In: 65}, {In: 10}, {In: 64}}
	med, tick, stable, drops := summarizeGame(s)
	if med != 64 || tick != 64 || drops != 1 || stable != 80 {
		t.Errorf("summarize: %v %v %v %v", med, tick, stable, drops)
	}
	if !newerVer("v0.13.0-beta", "0.12.0-beta") || newerVer("v0.12.0-beta", "0.12.0-beta") || !newerVer("v0.12.0", "0.12.0-beta") || newerVer("v0.11.9", "0.12.0-beta") {
		t.Error("Versionsvergleich falsch")
	}
}

func TestMonthReport(t *testing.T) {
	a := newTestApp(t)
	dir := t.TempDir()
	a.traffic = newTraffic(a, filepath.Join(dir, "v.json"))
	a.outages = newOutages(a, filepath.Join(dir, "a.json"))
	a.pctest = newPCTester(a, filepath.Join(dir, "p.json"))
	a.day.d.Daily = map[string]map[string]*DayAgg{
		"2026-09-01": {"Traffic": {Sent: 3600, Recv: 3600, Sum: 36000, JSum: 300, JN: 3500, Mins: 60, Host: "de-ber-wg-002"}},
		"2026-09-02": {"Traffic": {Sent: 3600, Recv: 3564, Sum: 39204, JSum: 300, JN: 3500, Mins: 60, Host: "de-dus-wg-102"}},
	}
	a.day.d.Counts = map[string]map[string]int{"2026-09": {"wechsel": 2, "warnung": 1}}
	a.traffic.d.Days["2026-09-01"] = &DayUse{RX: 10e9, TX: 1e9, VPNRX: 9e9}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)
	r := a.BuildMonth("2026-09", now)
	if !r.Complete || len(r.Tunnels) != 1 || r.Tunnels[0].Ping != 10.5 || r.Tunnels[0].Loss != 0.5 || len(r.Tunnels[0].Servers) != 2 || r.Switches != 2 || r.Usage.RX != 10e9 {
		t.Errorf("Monatsbericht falsch: %+v", r)
	}
	if r.Text == "" {
		t.Error("kein Text")
	}
}

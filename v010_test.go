package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestParseInfo(t *testing.T) {
	out := `WAN=eth2

FASTPING=1
HASWG=1
EP wgclient1 PUBA= 185.65.135.70:51820
EP wgclient2 PUBB= 193.32.248.66:51820
HS wgclient1 PUBA= 1700000000
HS wgclient2 PUBB= 0
TR wgclient1 PUBA= 1000 2000
LOAD 0.42 0.30 0.20 1/100 123
NPROC 4
MEM MemTotal: 1000000
MEM MemAvailable: 600000
TEMP 51234
TEMP 48000
UP 3600.5
NOW 1700000030
MODEL=GL.iNet GL-BE14000
`
	inf := parseInfo(out)
	if inf.WAN != "eth2" || !inf.FastPing || !inf.HasWG || inf.Model != "GL.iNet GL-BE14000" {
		t.Fatalf("Grundwerte falsch: %+v", inf)
	}
	if len(inf.Tunnels) != 2 {
		t.Fatalf("2 Tunnel erwartet, %d", len(inf.Tunnels))
	}
	a, b := inf.Tunnels[0], inf.Tunnels[1]
	if a.IP != "185.65.135.70" || a.HSAge != 30 || a.RX != 1000 || a.TX != 2000 {
		t.Errorf("Tunnel 1 falsch: %+v", a)
	}
	if b.HSAge != -1 || b.Handshake != 0 {
		t.Errorf("Tunnel 2 ohne Handshake erwartet: %+v", b)
	}
	if inf.Load1 != 0.42 || inf.NProc != 4 || inf.MemTotal != 1000000 || inf.MemAvail != 600000 {
		t.Errorf("Last/RAM falsch: %+v", inf)
	}
	if inf.TempC < 51.2 || inf.TempC > 51.3 || inf.UptimeS != 3600.5 {
		t.Errorf("Temp/Uptime falsch: %v %v", inf.TempC, inf.UptimeS)
	}
	// Tunnel-Schnittstelle darf nicht als WAN gelten
	if parseInfo("WAN=wgclient1\n").WAN != "" {
		t.Error("wg-Schnittstelle als WAN akzeptiert")
	}
	_ = parseInfo("\n\n   \nEP\nHS x\n") // darf nicht abstürzen
}

const glTunnels = `{"tunnels":[
 {"tunnel_id":6397,"name":"Porn","enabled":true,
  "via":{"type":"wireguard","via":"wgclient1","configs":[{"group_id":10003,"id_list":[2047]}]},
  "from":{"type":"default"},
  "to":{"type":"domain","manual":true,"domain_list":"a.com\nb.com","domain_list_len":2}},
 {"tunnel_id":9548,"name":"Traffic","enabled":true,
  "via":{"type":"wireguard","via":"wgclient2","configs":[{"group_id":10003,"id_list":[2002]}]},
  "from":{"type":"default"},"to":{"type":"default"}},
 {"tunnel_id":1,"name":"WAN","via":{"type":"wan"}}
]}`

func TestParseGL(t *testing.T) {
	tun, err := parseGLTunnels(json.RawMessage(glTunnels))
	if err != nil {
		t.Fatal(err)
	}
	if len(tun) != 2 {
		t.Fatalf("2 WireGuard-Tunnel erwartet, %d", len(tun))
	}
	if tun[0].TunnelID != 6397 || tun[0].Iface != "wgclient1" || tun[0].GroupID != 10003 || !reflect.DeepEqual(tun[0].PeerIDs, []int{2047}) || tun[0].Name != "Porn" {
		t.Errorf("Tunnel 1 falsch: %+v", tun[0])
	}
	peers, err := parseGLPeers(json.RawMessage(`{"configs":{"wireguard":[{"group_id":10003,"peers":[
		{"peer_id":2002,"name":"Germany_de-ber-wg-002","end_point":"1.2.3.4:51820"},
		{"peer_id":2047,"name":"Sweden_SE-MMA-WG-003"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if peers[2002].Host != "de-ber-wg-002" || peers[2047].Host != "se-mma-wg-003" || peers[2002].GroupID != 10003 {
		t.Errorf("Peers falsch: %+v", peers)
	}
}

func TestBuildSetTunnel(t *testing.T) {
	tun, _ := parseGLTunnels(json.RawMessage(glTunnels))
	// Domain-Tunnel: Domainliste bleiben, domain_list_len fliegt raus
	p := buildSetTunnel(tun[0], []int{2050})
	b, _ := json.Marshal(p)
	want := `{"from":{"type":"default"},"to":{"domain_list":"a.com\nb.com","manual":true,"type":"domain"},"tunnel_id":6397,"via":{"configs":[{"group_id":10003,"id_list":[2050]}],"type":"wireguard"}}`
	if string(b) != want {
		t.Errorf("Domain-Tunnel:\n got %s\nwant %s", b, want)
	}
	p = buildSetTunnel(tun[1], []int{2003})
	b, _ = json.Marshal(p)
	want = `{"from":{"type":"default"},"to":{"type":"default"},"tunnel_id":9548,"via":{"configs":[{"group_id":10003,"id_list":[2003]}],"type":"wireguard"}}`
	if string(b) != want {
		t.Errorf("Standard-Tunnel:\n got %s\nwant %s", b, want)
	}
	// Original darf nicht verändert werden
	if _, ok := tun[0].Raw["to"].(map[string]any)["domain_list_len"]; !ok {
		t.Error("Rohdaten wurden verändert")
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		name string
		w    WindowStats
		best float64
		have bool
		bad  bool
	}{
		{"zu wenig Daten", WindowStats{N: 30, Recv: 10, Loss: 66, Avg: 50}, 10, true, false},
		{"Verlust", WindowStats{N: 100, Recv: 90, Loss: 10, Avg: 11}, 10, true, true},
		{"gut", WindowStats{N: 100, Recv: 100, Avg: 12}, 10, true, false},
		{"langsam", WindowStats{N: 100, Recv: 100, Avg: 40}, 10, true, true},
		{"langsam ohne Vergleich", WindowStats{N: 100, Recv: 100, Avg: 40}, 0, false, false},
		{"+15 ms aber nicht 1,5x", WindowStats{N: 100, Recv: 100, Avg: 50}, 35, true, false},
	}
	for _, c := range cases {
		if bad, _ := verdict(c.w, c.best, c.have, 5, 15); bad != c.bad {
			t.Errorf("%s: bad=%v, erwartet %v", c.name, bad, c.bad)
		}
	}
}

func TestComputeStability(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var e []HistEntry
	for i := int64(0); i < 4; i++ {
		ts := now.Unix() - i*900
		e = append(e,
			HistEntry{T: ts, CC: "de", Host: "a", Avg: 10},
			HistEntry{T: ts, CC: "de", Host: "b", Avg: 12},
			HistEntry{T: ts, CC: "de", Host: "c", Avg: 20},
		)
	}
	e = append(e, HistEntry{T: now.Unix(), CC: "de", Host: "d", Avg: 10}) // zu wenig Daten
	e[1].Loss = 10                                                        // b einmal mit Verlust
	e = append(e, HistEntry{T: now.Unix() - 10*86400, CC: "de", Host: "a", Avg: 99})
	s := computeStability(e, 7*24*time.Hour, now)
	if s["a"] != 100 || s["b"] != 75 || s["c"] != 0 {
		t.Errorf("Stabilität falsch: %v", s)
	}
	if _, ok := s["d"]; ok {
		t.Error("d hat zu wenig Daten")
	}
}

func TestSortBoard(t *testing.T) {
	rows := []BoardRow{
		{Relay: Relay{Host: "none"}},
		{Relay: Relay{Host: "lossy"}, Median: 5, Loss: 10},
		{Relay: Relay{Host: "slow"}, Median: 20},
		{Relay: Relay{Host: "fast"}, Median: 10},
		{Relay: Relay{Host: "fast2"}, Median: 10},
	}
	sortBoard(rows)
	var got []string
	for _, r := range rows {
		got = append(got, r.Host)
	}
	want := []string{"fast", "fast2", "slow", "lossy", "none"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Reihenfolge %v, erwartet %v", got, want)
	}
}

func TestConfigNormalize(t *testing.T) {
	c := Config{Lang: "fr", AlertLossPct: 0, BoardInterval: 1, ChartScale: "x", AutoScanMin: 3}
	c.normalize()
	if c.Lang != "de" || c.AlertLossPct != 5 || c.BoardInterval != 10 || c.ChartScale != "auto" || c.AutoScanMin != 60 || c.Favorites == nil {
		t.Errorf("normalize: %+v", c)
	}
	c = Config{AutoScanMin: 0}
	c.normalize()
	if c.AutoScanMin != 0 {
		t.Error("Auto-Rangliste 0 (aus) muss erhalten bleiben")
	}
}

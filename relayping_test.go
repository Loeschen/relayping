package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReplyRegex(t *testing.T) {
	m := reReply.FindStringSubmatch("64 bytes from 185.65.135.1: seq=12 ttl=57 time=10.914 ms")
	if m == nil || m[1] != "12" || m[2] != "10.914" {
		t.Fatalf("BusyBox-Ping-Zeile nicht erkannt: %v", m)
	}
	if reReply.FindStringSubmatch("PING 1.2.3.4 (1.2.3.4): 56 data bytes") != nil {
		t.Fatal("Kopfzeile darf nicht als Antwort zählen")
	}
}

func TestSortResults(t *testing.T) {
	r := []ScanResult{
		{Relay: Relay{Host: "tot"}, Loss: 100},
		{Relay: Relay{Host: "verlust"}, Loss: 10, Avg: 5, Recv: 9},
		{Relay: Relay{Host: "langsam"}, Avg: 20, Recv: 10},
		{Relay: Relay{Host: "schnell"}, Avg: 9, Recv: 10},
	}
	sortResults(r)
	want := []string{"schnell", "langsam", "verlust", "tot"}
	for i, h := range want {
		if r[i].Host != h {
			t.Fatalf("Platz %d: %s, erwartet %s", i+1, r[i].Host, h)
		}
	}
}

func TestMinuteBucket(t *testing.T) {
	var b minuteBucket
	for _, ms := range []float64{10, 12, -1, 11} {
		b.add(ms)
	}
	if b.sent != 4 || b.recv != 3 || b.mn != 10 || b.mx != 12 {
		t.Fatalf("falsche Werte: %+v", b)
	}
}

func TestFetchRelays(t *testing.T) {
	v1 := `{"countries":[{"name":"Germany","code":"de","cities":[{"name":"Frankfurt","code":"fra","relays":[
		{"hostname":"de-fra-wg-001","ipv4_addr_in":"185.209.196.1","public_key":"abc="},
		{"hostname":"de-fra-wg-002","ipv4_addr_in":"kaputt"},
		{"hostname":"de-fra-wg-003","ipv4_addr_in":"185.209.196.3"}]}]}]}`
	www := `[{"hostname":"de-fra-wg-001","active":true,"owned":true,"provider":"31173","network_port_speed":10},
		{"hostname":"de-fra-wg-003","active":false}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1" {
			w.Write([]byte(v1))
		} else {
			w.Write([]byte(www))
		}
	}))
	defer srv.Close()
	apiV1, apiWWW = srv.URL+"/v1", srv.URL+"/www"
	list, err := fetchRelays()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Host != "de-fra-wg-001" || list[0].City != "Frankfurt" || list[0].CountryCode != "de" || list[0].Provider != "31173" {
		t.Fatalf("unerwartete Liste: %+v", list)
	}
}

func TestInputGuards(t *testing.T) {
	for _, s := range []string{"eth0", "wan", "br-lan.1"} {
		if !reIface.MatchString(s) {
			t.Fatalf("%s sollte gültig sein", s)
		}
	}
	for _, s := range []string{"eth0; reboot", "$(id)", "a b", ""} {
		if reIface.MatchString(s) {
			t.Fatalf("%q darf nicht als Schnittstelle durchgehen", s)
		}
	}
	if reHost.MatchString("192.168.8.1;reboot") || !reHost.MatchString("192.168.8.1") {
		t.Fatal("Router-Adresse falsch geprüft")
	}
}

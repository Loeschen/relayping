package main

import (
	"testing"
	"time"
)

const blockOut = `BEGIN de.pornhub.com
DE Server:		192.168.178.1
DE Address:	192.168.178.1:53
DE 
DE Non-authoritative answer:
DE de.pornhub.com	canonical name = notice.cuii.info
DE Name:	notice.cuii.info
DE Address: 104.21.3.4
VPN Server:		10.64.0.1
VPN Address:	10.64.0.1:53
VPN Non-authoritative answer:
VPN Name:	de.pornhub.com
VPN Address: 66.254.114.41
HTTP 200 https://de.pornhub.com/
END de.pornhub.com
BEGIN example.com
DE Non-authoritative answer:
DE Name:	example.com
DE Address: 93.184.216.34
VPN Name:	example.com
VPN Address: 93.184.216.34
HTTP 200 https://example.com/
END example.com
BEGIN gone.example
DE ** server can't find gone.example: NXDOMAIN
VPN Name:	gone.example
VPN Address: 1.2.3.4
HTTP 451 https://gone.example/
END gone.example
BEGIN dead.example
DE ** server can't find dead.example: NXDOMAIN
VPN ** server can't find dead.example: NXDOMAIN
HTTP 000 https://dead.example/
END dead.example
DONE`

func TestBlockParse(t *testing.T) {
	m := parseBlock(blockOut)
	want := map[string][2]string{
		"de.pornhub.com": {"gesperrt", "erreichbar"},
		"example.com":    {"frei", "erreichbar"},
		"gone.example":   {"gesperrt", "gesperrt"},
		"dead.example":   {"unbekannt", "fehler"},
	}
	for d, w := range want {
		r, ok := m[d]
		if !ok {
			t.Fatalf("%s fehlt", d)
		}
		classify(&r, true, true)
		if r.DE != w[0] || r.VPN != w[1] {
			t.Errorf("%s: DE=%s VPN=%s (Detail %q, IPs %v/%v), erwartet %v", d, r.DE, r.VPN, r.DEDetail, r.IPsDE, r.IPsVPN, w)
		}
	}
}

func TestCleanDomain(t *testing.T) {
	cases := map[string]string{"https://WWW.Example.com/path?x": "www.example.com", "*.foo.de": "foo.de", "bad domain": "", "a.b": "a.b", "x;rm -rf": "", "foo.de.": "foo.de"}
	for in, want := range cases {
		if got := cleanDomain(in); got != want {
			t.Errorf("%q -> %q, erwartet %q", in, got, want)
		}
	}
	list := map[string]bool{"pornhub.com": true}
	if !inListParent("de.pornhub.com", list) || inListParent("example.com", list) {
		t.Error("inListParent falsch")
	}
}

func TestGeoRecommend(t *testing.T) {
	rows := []CountryRow{
		{CC: "fr", Rule: adultRules["fr"], Best: &CountryBest{Avg: 9}},
		{CC: "nl", Rule: adultRules["nl"], Best: &CountryBest{Avg: 12}},
		{CC: "dk", Rule: adultRules["dk"], Best: &CountryBest{Avg: 11, Loss: 5}},
		{CC: "se", Rule: adultRules["se"]},
	}
	sortCountries(rows)
	if rows[0].CC != "fr" || rows[1].CC != "nl" || rows[2].CC != "dk" || rows[3].CC != "se" {
		t.Errorf("Reihenfolge: %v %v %v %v", rows[0].CC, rows[1].CC, rows[2].CC, rows[3].CC)
	}
	_ = time.Now
}

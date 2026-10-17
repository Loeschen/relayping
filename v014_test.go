package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseInfoAsus(t *testing.T) {
	out := `PLAT=asus
WAN=eth0
FASTPING=1
HASWG=1
EP wgc1 KEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= 185.213.154.68:51820
HS wgc1 KEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= 1791000000
MODEL=
MODEL=ASUS RT-AX86U
FW=3.0.0.4.388.8_2
THIRD=merlin
WGC 1 1 Mullvad Frankfurt
WGC 2 0
DEFRT wgc1
NOW 1791000010
`
	inf := parseInfo(out)
	if inf.Platform != "asus" || inf.Model != "ASUS RT-AX86U" || !inf.Merlin || !strings.Contains(inf.Firmware, "388.8_2") || !strings.Contains(inf.Firmware, "Merlin") {
		t.Fatalf("Plattform falsch: %+v", inf)
	}
	nt := inf.Native["wgc1"]
	if nt.Unit != 1 || !nt.Enabled || nt.Desc != "Mullvad Frankfurt" || inf.DefIface != "wgc1" {
		t.Fatalf("WGC falsch: %+v %q", nt, inf.DefIface)
	}
	a := newTestApp(t)
	tun := inf.Tunnels[0]
	a.nativeTunnel(&inf, &tun)
	if tun.TunnelID != 101 || tun.Name != "Mullvad Frankfurt" || !tun.CanSwitch {
		t.Fatalf("Tunnel falsch: %+v", tun)
	}
}

func TestParseInfoOpenWrt(t *testing.T) {
	out := `PLAT=openwrt
FW=OpenWrt 24.10.0
UPEER wg0 cfg0a1b2c
UPEER wg1 @wireguard_wg1[0]
UPEER wg1 @wireguard_wg1[1]
UPEER wg2 bad;rm
EP wg0 KEY0 1.2.3.4:51820
EP wg1 KEY1 1.2.3.5:51820
`
	inf := parseInfo(out)
	if inf.Platform != "openwrt" || inf.Firmware != "OpenWrt 24.10.0" {
		t.Fatalf("%+v", inf)
	}
	if inf.Native["wg0"].Section != "cfg0a1b2c" || inf.Native["wg0"].Peers != 1 || inf.Native["wg1"].Peers != 2 {
		t.Fatalf("UPEER falsch: %+v", inf.Native)
	}
	if _, ok := inf.Native["wg2"]; ok {
		t.Fatal("ungültiger Abschnitt angenommen")
	}
	a := newTestApp(t)
	t0, t1 := inf.Tunnels[0], inf.Tunnels[1]
	a.nativeTunnel(&inf, &t0)
	a.nativeTunnel(&inf, &t1)
	if !t0.CanSwitch || t1.CanSwitch || t0.TunnelID == t1.TunnelID || t0.TunnelID < 200 {
		t.Fatalf("CanSwitch/ID falsch: %+v %+v", t0, t1)
	}
}

func TestNativeCmds(t *testing.T) {
	key := "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdE="
	e := nativeEndpoint{Addr: "185.213.154.68", Port: "51820", Key: key}
	c, err := nativeSetCmd("asus", "wgc2", NativeTun{Unit: 2}, e)
	if err != nil || !strings.Contains(c, "nvram set wgc2_ep_addr='185.213.154.68'") || !strings.Contains(c, `service "restart_wgc 2"`) || !strings.Contains(c, "wgc2_ppub='"+key+"'") {
		t.Fatalf("asus: %v %s", err, c)
	}
	c, err = nativeSetCmd("openwrt", "wg0", NativeTun{Section: "@wireguard_wg0[0]"}, e)
	if err != nil || !strings.Contains(c, "uci set 'network.@wireguard_wg0[0].endpoint_host=185.213.154.68'") || !strings.Contains(c, "ifup 'wg0'") {
		t.Fatalf("openwrt: %v %s", err, c)
	}
	// Einschleusen verhindern
	for _, bad := range []nativeEndpoint{{Addr: "1.2.3.4;reboot", Port: "51820", Key: key}, {Addr: "1.2.3.4", Port: "5x", Key: key}, {Addr: "1.2.3.4", Port: "51820", Key: "abc'"}} {
		if _, err := nativeSetCmd("asus", "wgc1", NativeTun{Unit: 1}, bad); err == nil {
			t.Fatalf("ungültige Werte angenommen: %+v", bad)
		}
	}
	if _, err := nativeSetCmd("openwrt", "wg0", NativeTun{Section: "x';reboot;'"}, e); err == nil {
		t.Fatal("ungültiger Abschnitt angenommen")
	}
	p, ok := parseNativePrev("PREV 1.2.3.4 51820 " + key + "\n")
	if !ok || p.Addr != "1.2.3.4" {
		t.Fatalf("prev: %+v", p)
	}
	p, ok = parseNativePrev("PREV de-fra.example 51820 " + key)
	if !ok || p.Addr != "de-fra.example" {
		t.Fatal("Hostname als Gegenstelle nicht angenommen")
	}
	if _, ok := parseNativePrev("PREV 1.2.3.4 51820 "); ok {
		t.Fatal("unvollständige Einstellung angenommen")
	}
}

func TestDigestRFC2617(t *testing.T) {
	ch := `Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"`
	s, err := digestAuthC(ch, "GET", "/dir/index.html", "Mufasa", "Circle Of Life", "0a4f113b")
	if err != nil || !strings.Contains(s, `response="6629fae49393a05397450978507c4ef1"`) || !strings.Contains(s, `opaque="5ccc069c403ebaf9f0171e9517f40e41"`) {
		t.Fatalf("%v %s", err, s)
	}
}

func TestFritzXML(t *testing.T) {
	desc := `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><systemVersion><Display>284.08.01</Display></systemVersion><device><friendlyName>FRITZ!Box 5590 Fiber</friendlyName><modelName>FRITZ!Box 5590 Fiber</modelName>
<serviceList><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service></serviceList>
<deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/igdupnp/control/WANCommonIFC1</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/igdupnp/control/WANIPConn1</controlURL></service></serviceList></device></deviceList></device></root>`
	d := parseFritzDesc(desc)
	if d.Model != "FRITZ!Box 5590 Fiber" || d.Display != "284.08.01" || len(d.Services) != 3 {
		t.Fatalf("%+v", d)
	}
	if s, ok := d.find("WANIPConnection:"); !ok || s.URL != "/igdupnp/control/WANIPConn1" {
		t.Fatal("Dienst nicht gefunden")
	}
	resp := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetAddonInfosResponse xmlns:u="urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1">
<NewByteSendRate>1200</NewByteSendRate><NewByteReceiveRate>98000</NewByteReceiveRate><NewX_AVM_DE_TotalBytesSent64>5000000000</NewX_AVM_DE_TotalBytesSent64><NewX_AVM_DE_TotalBytesReceived64>90000000000</NewX_AVM_DE_TotalBytesReceived64>
</u:GetAddonInfosResponse></s:Body></s:Envelope>`
	v, err := parseSOAP(resp)
	if err != nil || atou(v["NewX_AVM_DE_TotalBytesReceived64"]) != 90000000000 || v["NewByteReceiveRate"] != "98000" {
		t.Fatalf("%v %+v", err, v)
	}
	fault := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>401</errorCode><errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`
	if _, err := parseSOAP(fault); err == nil || !strings.Contains(err.Error(), "Invalid Action") {
		t.Fatalf("Fehler nicht erkannt: %v", err)
	}
	if u := pickFritzUser(`&lt;List&gt;&lt;Username&gt;admin&lt;/Username&gt;&lt;Username last_user="1"&gt;fritz3456&lt;/Username&gt;&lt;/List&gt;`); u != "fritz3456" {
		t.Fatalf("Benutzer: %q", u)
	}
	for in, want := range map[string]string{"192.168.178.1": "http://192.168.178.1:49000", "fritz.box:49000": "http://fritz.box:49000", "http://192.168.178.1/": "http://192.168.178.1:49000"} {
		if got, err := fritzBase(in); err != nil || got != want {
			t.Fatalf("%s: %s %v", in, got, err)
		}
	}
	for _, bad := range []string{"a b", "1.2.3.4:99999", "x';reboot"} {
		if _, err := fritzBase(bad); err == nil {
			t.Fatalf("ungültige Adresse angenommen: %s", bad)
		}
	}
}

func TestFritzUsage(t *testing.T) {
	var u fritzUsage
	d := time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)
	u.add(1000, 100, d)
	u.add(3000, 300, d.Add(time.Minute))
	u.add(500, 50, d.Add(2*time.Minute)) // Neustart: Zähler fängt neu an
	rx, tx, mrx, _ := u.sums(d)
	if rx != 2500 || tx != 250 || mrx != 2500 {
		t.Fatalf("%d %d %d", rx, tx, mrx)
	}
}

package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Server-Wechsel auf Routern ohne GL.iNet-Schnittstelle:
//   - OpenWrt: der WireGuard-Peer steht in /etc/config/network (uci), danach "ifup <iface>"
//   - Asus (Asuswrt-Merlin und neuere Original-Firmware): nvram wgcN_ep_addr/ep_port/ppub,
//     danach "service restart_wgc N" – dieselben Werte, die die Asus-Oberfläche setzt.
// Mullvad akzeptiert denselben WireGuard-Schlüssel auf allen Servern, deshalb reicht es,
// Gegenstelle und deren öffentlichen Schlüssel zu tauschen.

type NativeTun struct {
	Unit    int    // Asus: 1–5
	Section string // OpenWrt: uci-Abschnitt des Peers
	Peers   int    // OpenWrt: Anzahl Peers der Schnittstelle (nur 1 ist umstellbar)
	Desc    string
	Enabled bool
}

var reWGKey = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

const nativeBaseAsus, nativeBaseOpenWrt = 100, 200

// nativeTunnel ergänzt Name, ID und Umstellbarkeit eines Tunnels (OpenWrt/Asus).
func (a *App) nativeTunnel(inf *RouterInfo, t *Tunnel) {
	nt, ok := inf.Native[t.Iface]
	switch inf.Platform {
	case "asus":
		if ok && nt.Unit > 0 {
			t.TunnelID = nativeBaseAsus + nt.Unit
			t.Name = nt.Desc
			if t.Name == "" {
				t.Name = fmt.Sprintf("VPN-Client %d", nt.Unit)
			}
			t.CanSwitch = true
		}
	case "openwrt":
		var ifs []string
		for k := range inf.Native {
			ifs = append(ifs, k)
		}
		sort.Strings(ifs)
		for i, k := range ifs {
			if k == t.Iface {
				t.TunnelID = nativeBaseOpenWrt + i + 1
			}
		}
		t.Name = t.Iface
		t.CanSwitch = ok && nt.Peers == 1 && nt.Section != ""
	}
}

func (r *Router) isNative() bool {
	_, _, inf := r.State()
	return inf.Platform == "openwrt" || inf.Platform == "asus"
}

// nativeEndpoint: aktuelle Einstellung (für den Rückfall).
type nativeEndpoint struct {
	Addr, Port, Key string
}

func (e nativeEndpoint) valid() bool {
	p, err := strconv.Atoi(e.Port)
	return reHost.MatchString(e.Addr) && err == nil && p > 0 && p < 65536 && reWGKey.MatchString(e.Key)
}

func nativeReadCmd(plat string, nt NativeTun) string {
	if plat == "asus" {
		n := strconv.Itoa(nt.Unit)
		return `echo "PREV $(nvram get wgc` + n + `_ep_addr) $(nvram get wgc` + n + `_ep_port) $(nvram get wgc` + n + `_ppub)"`
	}
	s := "network." + nt.Section
	return `echo "PREV $(uci -q get '` + s + `.endpoint_host') $(uci -q get '` + s + `.endpoint_port') $(uci -q get '` + s + `.public_key')"`
}

func parseNativePrev(out string) (nativeEndpoint, bool) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 4 && f[0] == "PREV" {
			e := nativeEndpoint{Addr: f[1], Port: f[2], Key: f[3]}
			return e, e.valid()
		}
		if len(f) == 3 && f[0] == "PREV" { // Port nicht gesetzt (OpenWrt-Standard 51820)
			e := nativeEndpoint{Addr: f[1], Port: "51820", Key: f[2]}
			return e, e.valid()
		}
	}
	return nativeEndpoint{}, false
}

// nativeSetCmd baut den Befehl, der eine Gegenstelle einstellt. Alle Werte sind vorher geprüft.
func nativeSetCmd(plat, iface string, nt NativeTun, e nativeEndpoint) (string, error) {
	if !e.valid() || !reIface.MatchString(iface) {
		return "", errors.New("ungültige Werte")
	}
	if plat == "asus" {
		if nt.Unit < 1 || nt.Unit > 5 {
			return "", errors.New("ungültige Client-Nummer")
		}
		n := strconv.Itoa(nt.Unit)
		return fmt.Sprintf(`nvram set wgc%[1]s_ep_addr='%[2]s' && nvram set wgc%[1]s_ep_port='%[3]s' && nvram set wgc%[1]s_ppub='%[4]s' && nvram commit && service "restart_wgc %[1]s" >/dev/null 2>&1; echo OK`,
			n, e.Addr, e.Port, e.Key), nil
	}
	if !reUCISection.MatchString(nt.Section) {
		return "", errors.New("ungültiger uci-Abschnitt")
	}
	s := "network." + nt.Section
	return fmt.Sprintf(`uci set '%[1]s.public_key=%[2]s' && uci set '%[1]s.endpoint_host=%[3]s' && uci set '%[1]s.endpoint_port=%[4]s' && uci commit network && (ifup '%[5]s' >/dev/null 2>&1 || ubus call network.interface.%[5]s up >/dev/null 2>&1); echo OK`,
		s, e.Key, e.Addr, e.Port, iface), nil
}

// nativeTarget baut für den Switcher Anwenden und Rückfall.
func (a *App) nativeTarget(tunnelID int) (swTarget, error) {
	r := a.router
	r.Refresh()
	_, _, inf := r.State()
	var tun Tunnel
	found := false
	for _, t := range inf.Tunnels {
		if t.TunnelID == tunnelID {
			tun, found = t, true
		}
	}
	if !found {
		return swTarget{}, errors.New(a.tr("Tunnel nicht gefunden", "Tunnel not found"))
	}
	nt := inf.Native[tun.Iface]
	if !tun.CanSwitch {
		return swTarget{}, errors.New(a.tr("Dieser Tunnel lässt sich nicht umstellen (nur Tunnel mit genau einer Gegenstelle)", "This tunnel cannot be switched (only tunnels with exactly one peer)"))
	}
	plat := inf.Platform
	out, err := r.Run(nativeReadCmd(plat, nt), 10*time.Second)
	if err != nil {
		return swTarget{}, err
	}
	prev, ok := parseNativePrev(out)
	if !ok {
		return swTarget{}, errors.New(a.tr("Die aktuelle Tunnel-Einstellung ist nicht lesbar – ohne sie gäbe es keinen sicheren Rückfall", "Cannot read the current tunnel setting – without it there is no safe way back"))
	}
	set := func(e nativeEndpoint) error {
		cmd, err := nativeSetCmd(plat, tun.Iface, nt, e)
		if err != nil {
			return err
		}
		out, err := r.Run(cmd, 60*time.Second)
		if err != nil {
			return err
		}
		if !strings.Contains(out, "OK") {
			return errors.New(strings.TrimSpace(out))
		}
		return nil
	}
	name := tun.Name
	if name == "" {
		name = tun.Iface
	}
	oldIP := prev.Addr
	if net.ParseIP(oldIP) == nil {
		if rl, ok := a.relays.Host(tun.Host); ok {
			oldIP = rl.IPv4
		}
	}
	return swTarget{
		ID: tunnelID, Name: name, Iface: tun.Iface, Host: tun.Host, OldIP: oldIP,
		Panel: a.platformPanel(plat),
		Apply: func(rl Relay) error {
			if !reWGKey.MatchString(rl.PubKey) || net.ParseIP(rl.IPv4) == nil {
				return errors.New(a.tr("Für diesen Server fehlt der öffentliche Schlüssel in der Serverliste", "The server list has no public key for this server"))
			}
			return set(nativeEndpoint{Addr: rl.IPv4, Port: "51820", Key: rl.PubKey})
		},
		Restore: func() error { return set(prev) },
	}, nil
}

func (a *App) platformPanel(plat string) string {
	switch plat {
	case "asus":
		return a.tr("in der Asus-Oberfläche (VPN → VPN-Client)", "in the Asus web interface (VPN → VPN Client)")
	case "openwrt":
		return a.tr("in LuCI (Netzwerk → Schnittstellen)", "in LuCI (Network → Interfaces)")
	}
	return a.tr("im GL.iNet-Panel", "in the GL.iNet panel")
}

func platformLabel(plat string) string {
	switch plat {
	case "glinet":
		return "GL.iNet"
	case "openwrt":
		return "OpenWrt"
	case "asus":
		return "Asus"
	}
	return ""
}

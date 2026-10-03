package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Die GL.iNet-Oberfläche spricht mit /rpc auf dem Router. Lokal auf dem Router
// (also über unsere SSH-Verbindung) nimmt dieser Endpunkt Aufrufe mit dem
// Header "glinet: 1" auch ohne Web-Sitzung an – denselben Weg nutzt GL.iNet für
// eigene Werkzeuge. Wir rufen damit nur drei Methoden auf:
//
//	vpn-client.get_tunnel, vpn-client.get_all_config_list, vpn-client.set_tunnel
const rpcCmd = `command -v curl >/dev/null 2>&1 || { echo '{"error":{"code":-1,"message":"curl fehlt"}}'; exit 0; }
curl -s -m 25 -H 'glinet: 1' -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1/rpc`

var rpcID atomic.Int64

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RPC ruft eine Methode der GL.iNet-Schnittstelle auf dem Router auf.
func (r *Router) RPC(module, method string, params any, out any) error {
	if params == nil {
		params = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": rpcID.Add(1), "method": "call",
		"params": []any{"", module, method, params},
	})
	if err != nil {
		return err
	}
	s, err := r.Session()
	if err != nil {
		return err
	}
	defer s.Close()
	s.Stdin = strings.NewReader(string(body))
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() { b, err := s.Output(rpcCmd); ch <- res{b, err} }()
	var rr res
	select {
	case rr = <-ch:
	case <-time.After(35 * time.Second):
		s.Close()
		return errors.New(r.app.tr("Router-Schnittstelle antwortet nicht", "router interface not responding"))
	}
	if len(rr.b) == 0 {
		if rr.err != nil {
			return rr.err
		}
		return errors.New(r.app.tr("leere Antwort der Router-Schnittstelle", "empty answer from router interface"))
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(rr.b, &env); err != nil {
		return fmt.Errorf(r.app.tr("unerwartete Antwort der Router-Schnittstelle: %.120s", "unexpected answer from router interface: %.120s"), string(rr.b))
	}
	if env.Error != nil {
		return fmt.Errorf("%s.%s: %s (%d)", module, method, env.Error.Message, env.Error.Code)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// ---------- Modell der GL.iNet-Tunnel ----------

type GLPeer struct {
	ID      int    `json:"peer_id"`
	Name    string `json:"name"`
	EndPt   string `json:"end_point"`
	Host    string `json:"-"`
	GroupID int    `json:"-"`
}

type GLTunnel struct {
	TunnelID int            `json:"tunnel_id"`
	Name     string         `json:"name"`
	Enabled  bool           `json:"enabled"`
	Iface    string         `json:"iface"`
	GroupID  int            `json:"group_id"`
	PeerIDs  []int          `json:"peer_ids"`
	Host     string         `json:"host"` // aktueller (erster) Server
	Raw      map[string]any `json:"-"`
}

type GLState struct {
	OK      bool
	Err     string
	Tunnels []GLTunnel
	Peers   map[int]GLPeer    // peer_id -> Peer
	ByName  map[string]GLPeer // Mullvad-Hostname -> Peer
	Fetched time.Time
}

func (g *GLState) ByIface(iface string) (GLTunnel, bool) {
	if g == nil {
		return GLTunnel{}, false
	}
	for _, t := range g.Tunnels {
		if t.Iface == iface {
			return t, true
		}
	}
	return GLTunnel{}, false
}

func (g *GLState) ByID(id int) (GLTunnel, bool) {
	if g == nil {
		return GLTunnel{}, false
	}
	for _, t := range g.Tunnels {
		if t.TunnelID == id {
			return t, true
		}
	}
	return GLTunnel{}, false
}

// peerHost: "Germany_de-ber-wg-002" -> "de-ber-wg-002"
func peerHost(name string) string {
	if i := strings.LastIndex(name, "_"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// parseGLTunnels wertet get_tunnel aus.
func parseGLTunnels(raw json.RawMessage) ([]GLTunnel, error) {
	var res struct {
		Tunnels []map[string]any `json:"tunnels"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	var out []GLTunnel
	for _, t := range res.Tunnels {
		via, _ := t["via"].(map[string]any)
		if via == nil || via["type"] != "wireguard" {
			continue
		}
		g := GLTunnel{Raw: t}
		g.TunnelID = toInt(t["tunnel_id"])
		g.Name, _ = t["name"].(string)
		g.Enabled, _ = t["enabled"].(bool)
		g.Iface, _ = via["via"].(string)
		if cfgs, ok := via["configs"].([]any); ok && len(cfgs) > 0 {
			if c0, ok := cfgs[0].(map[string]any); ok {
				g.GroupID = toInt(c0["group_id"])
				if ids, ok := c0["id_list"].([]any); ok {
					for _, id := range ids {
						g.PeerIDs = append(g.PeerIDs, toInt(id))
					}
				}
			}
		}
		if g.TunnelID != 0 && g.GroupID != 0 && len(g.PeerIDs) > 0 {
			out = append(out, g)
		}
	}
	return out, nil
}

// parseGLPeers wertet get_all_config_list aus (nur WireGuard-Gruppen).
func parseGLPeers(raw json.RawMessage) (map[int]GLPeer, error) {
	var res struct {
		Configs struct {
			WireGuard []struct {
				GroupID int      `json:"group_id"`
				Peers   []GLPeer `json:"peers"`
			} `json:"wireguard"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	out := map[int]GLPeer{}
	for _, g := range res.Configs.WireGuard {
		for _, p := range g.Peers {
			p.GroupID = g.GroupID
			p.Host = peerHost(p.Name)
			out[p.ID] = p
		}
	}
	return out, nil
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	}
	return 0
}

// buildSetTunnel baut die Parameter für set_tunnel so, wie die GL-Oberfläche sie
// sendet: Quelle und Ziel bleiben unverändert, nur der Server wird getauscht.
func buildSetTunnel(t GLTunnel, peerIDs []int) map[string]any {
	from, _ := t.Raw["from"].(map[string]any)
	if from == nil {
		from = map[string]any{"type": "default"}
	}
	to := map[string]any{}
	if src, ok := t.Raw["to"].(map[string]any); ok {
		for k, v := range src {
			if k == "domain_list_len" {
				continue
			}
			to[k] = v
		}
	}
	if to["type"] == nil {
		to["type"] = "default"
	}
	if to["type"] != "domain" {
		delete(to, "domain_list")
		delete(to, "manual")
	}
	ids := make([]any, len(peerIDs))
	for i, id := range peerIDs {
		ids[i] = id
	}
	return map[string]any{
		"via": map[string]any{
			"type":    "wireguard",
			"configs": []any{map[string]any{"group_id": t.GroupID, "id_list": ids}},
		},
		"from":      from,
		"to":        to,
		"tunnel_id": t.TunnelID,
	}
}

// RefreshGL liest Tunnel und Server-Profile aus der GL.iNet-Konfiguration.
func (r *Router) RefreshGL(withPeers bool) {
	st := &GLState{}
	r.mu.Lock()
	old := r.gl
	r.mu.Unlock()
	var raw json.RawMessage
	err := r.RPC("vpn-client", "get_tunnel", nil, &raw)
	if err == nil {
		st.Tunnels, err = parseGLTunnels(raw)
	}
	if err == nil {
		if withPeers || old == nil || old.Peers == nil || time.Since(old.Fetched) > 30*time.Minute {
			var praw json.RawMessage
			if err = r.RPC("vpn-client", "get_all_config_list", nil, &praw); err == nil {
				st.Peers, err = parseGLPeers(praw)
				st.Fetched = time.Now()
			}
		} else {
			st.Peers, st.Fetched = old.Peers, old.Fetched
		}
	}
	if err != nil {
		st.OK, st.Err = false, err.Error()
	} else {
		st.OK = true
		st.ByName = map[string]GLPeer{}
		for _, p := range st.Peers {
			st.ByName[p.Host] = p
		}
		for i := range st.Tunnels {
			t := &st.Tunnels[i]
			if p, ok := st.Peers[t.PeerIDs[0]]; ok {
				t.Host = p.Host
			}
		}
	}
	r.mu.Lock()
	r.gl = st
	r.mu.Unlock()
}

func (r *Router) GL() *GLState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gl
}

// ---------- Server-Wechsel ----------

type SwitchStatus struct {
	Running  bool      `json:"running"`
	TunnelID int       `json:"tunnel_id"`
	Name     string    `json:"name"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Stage    string    `json:"stage"` // senden, warten, ok, zurueck, fehler
	Message  string    `json:"message"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

type Switcher struct {
	app *App
	mu  sync.Mutex
	st  SwitchStatus
}

func (s *Switcher) Status() SwitchStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Switcher) set(fn func(st *SwitchStatus)) {
	s.mu.Lock()
	fn(&s.st)
	st := s.st
	s.mu.Unlock()
	s.app.broadcast("switch", st)
}

// Start prüft die Anfrage und wechselt im Hintergrund.
func (s *Switcher) Start(tunnelID int, host string) error {
	a := s.app
	r := a.router
	r.RefreshGL(false)
	gl := r.GL()
	if gl == nil || !gl.OK {
		reason := ""
		if gl != nil {
			reason = gl.Err
		}
		return fmt.Errorf(a.tr("Die Tunnel-Konfiguration des Routers ist nicht lesbar: %s", "Cannot read the router's tunnel configuration: %s"), reason)
	}
	t, ok := gl.ByID(tunnelID)
	if !ok {
		return errors.New(a.tr("Tunnel nicht gefunden", "Tunnel not found"))
	}
	target, ok := a.relays.Host(host)
	if !ok {
		return errors.New(a.tr("Unbekannter Server", "Unknown server"))
	}
	peer, ok := gl.ByName[target.Host]
	if !ok || peer.GroupID != t.GroupID {
		return fmt.Errorf(a.tr("Für %s gibt es auf dem Router kein Profil in der Mullvad-Gruppe dieses Tunnels", "There is no profile for %s in this tunnel's Mullvad group on the router"), target.Host)
	}
	cur, _ := a.relays.Host(t.Host)
	if cur.CountryCode != "" && cur.CountryCode != target.CountryCode {
		return fmt.Errorf(a.tr("Wechsel nur innerhalb des Landes (%s): So bleibt der Zweck des Tunnels erhalten. Länderwechsel bitte im GL.iNet-Panel.",
			"Switching only within the same country (%s), so the tunnel keeps its purpose. Change countries in the GL.iNet panel."), strings.ToUpper(cur.CountryCode))
	}
	if t.Host == target.Host && len(t.PeerIDs) == 1 {
		return errors.New(a.tr("Der Tunnel nutzt diesen Server bereits", "The tunnel already uses this server"))
	}
	s.mu.Lock()
	if s.st.Running {
		s.mu.Unlock()
		return errors.New(a.tr("Es läuft bereits ein Wechsel", "A switch is already in progress"))
	}
	s.st = SwitchStatus{Running: true, TunnelID: t.TunnelID, Name: t.Name, From: t.Host, To: target.Host, Stage: "senden", Started: time.Now()}
	s.mu.Unlock()
	go s.run(t, peer, target)
	return nil
}

func (s *Switcher) run(t GLTunnel, peer GLPeer, target Relay) {
	a := s.app
	r := a.router
	start := time.Now()
	finish := func(stage, msg string) {
		s.set(func(st *SwitchStatus) {
			st.Running, st.Stage, st.Message, st.Finished = false, stage, msg, time.Now()
		})
		a.csv.Switch(start, t.Name, t.Host, target.Host, stage, msg, time.Since(start))
		r.RefreshGL(false)
		r.Refresh()
		if stage == "ok" {
			a.startMonitor(target.Host, false)
		}
		a.notify(a.tr("Server-Wechsel", "Server switch"), msg)
	}
	s.set(func(st *SwitchStatus) {
		st.Message = fmt.Sprintf(a.tr("Stelle %s auf %s um …", "Switching %s to %s …"), t.Name, target.Host)
	})
	routerStart := r.routerNow()
	if err := r.RPC("vpn-client", "set_tunnel", buildSetTunnel(t, []int{peer.ID}), nil); err != nil {
		finish("fehler", fmt.Sprintf(a.tr("Der Router hat den Wechsel abgelehnt: %v", "The router rejected the switch: %v"), err))
		return
	}
	s.set(func(st *SwitchStatus) {
		st.Stage = "warten"
		st.Message = a.tr("Warte auf die WireGuard-Verbindung zum neuen Server …", "Waiting for the WireGuard connection to the new server …")
	})
	if r.waitHandshake(t.Iface, target.IPv4, routerStart, 35*time.Second) {
		finish("ok", fmt.Sprintf(a.tr("%s nutzt jetzt %s (%s).", "%s now uses %s (%s)."), t.Name, target.Host, target.City))
		return
	}
	// Rückfall auf die vorherige Einstellung
	s.set(func(st *SwitchStatus) {
		st.Stage = "zurueck"
		st.Message = a.tr("Keine Verbindung zum neuen Server – stelle den vorherigen wieder ein …", "No connection to the new server – restoring the previous one …")
	})
	if err := r.RPC("vpn-client", "set_tunnel", buildSetTunnel(t, t.PeerIDs), nil); err != nil {
		finish("fehler", fmt.Sprintf(a.tr("Wechsel fehlgeschlagen UND Rückfall abgelehnt (%v). Bitte im GL.iNet-Panel prüfen!", "Switch failed AND restoring was rejected (%v). Please check in the GL.iNet panel!"), err))
		return
	}
	oldIP := ""
	if old, ok := a.relays.Host(t.Host); ok {
		oldIP = old.IPv4
	}
	if oldIP != "" && r.waitHandshake(t.Iface, oldIP, r.routerNow(), 35*time.Second) {
		finish("zurueck", fmt.Sprintf(a.tr("%s antwortete nicht. %s nutzt wieder %s.", "%s did not respond. %s is back on %s."), target.Host, t.Name, t.Host))
		return
	}
	finish("fehler", a.tr("Rückfall eingestellt, aber noch keine Verbindung bestätigt. Bitte im GL.iNet-Panel prüfen.", "Restored the previous setting, but no connection confirmed yet. Please check in the GL.iNet panel."))
}

func (r *Router) routerNow() int64 {
	out, err := r.Run("date +%s", 10*time.Second)
	if err == nil {
		var v int64
		if _, err := fmt.Sscan(strings.TrimSpace(out), &v); err == nil && v > 0 {
			return v
		}
	}
	return time.Now().Unix()
}

// waitHandshake wartet, bis die Schnittstelle mit der gewünschten Gegenstelle
// einen Handshake hat, der nach "since" (Router-Uhr) stattfand.
func (r *Router) waitHandshake(iface, ip string, since int64, timeout time.Duration) bool {
	if !reIface.MatchString(iface) || net.ParseIP(ip) == nil {
		return false
	}
	deadline := time.Now().Add(timeout)
	// Ein Ping durch den Tunnel (Mullvad-Gateway 10.64.0.1) stößt den Handshake an,
	// falls gerade kein Verkehr über den Tunnel läuft.
	cmd := "(ping -c 1 -W 1 -I " + iface + " 10.64.0.1 >/dev/null 2>&1 &); wg show " + iface + " endpoints 2>/dev/null | sed 's/^/EP /'; wg show " + iface + " latest-handshakes 2>/dev/null | sed 's/^/HS /'"
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		out, err := r.Run(cmd, 10*time.Second)
		if err != nil {
			continue
		}
		key := ""
		hs := map[string]int64{}
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) == 3 && f[0] == "EP" {
				if h, _, err := net.SplitHostPort(f[2]); err == nil && h == ip {
					key = f[1]
				}
			}
			if len(f) == 3 && f[0] == "HS" {
				var v int64
				fmt.Sscan(f[2], &v)
				hs[f[1]] = v
			}
		}
		if key != "" && hs[key] >= since-1 && hs[key] > 0 {
			return true
		}
	}
	return false
}

// SwitchTargets liefert für die UI je Tunnel, ob und wohin gewechselt werden kann.
func (a *App) switchInfo() map[string]any {
	gl := a.router.GL()
	out := map[string]any{"available": false}
	if gl == nil {
		out["reason"] = a.tr("noch nicht geprüft", "not checked yet")
		return out
	}
	if !gl.OK {
		out["reason"] = gl.Err
		return out
	}
	out["available"] = true
	var ts []map[string]any
	for _, t := range gl.Tunnels {
		var hosts []string
		for h, p := range gl.ByName {
			if p.GroupID == t.GroupID {
				hosts = append(hosts, h)
			}
		}
		sort.Strings(hosts)
		ts = append(ts, map[string]any{"tunnel_id": t.TunnelID, "name": t.Name, "iface": t.Iface, "host": t.Host, "enabled": t.Enabled, "profiles": len(hosts)})
	}
	out["tunnels"] = ts
	return out
}

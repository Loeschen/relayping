package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Datenverbrauch: Der Router zählt jedes Byte seit dem letzten Neustart
// (/proc/net/dev der WAN-Schnittstelle, WireGuard je Tunnel). RelayPing liest
// die Zähler alle 10 Sekunden und schreibt die Zuwächse auf Tage. Läuft
// RelayPing eine Weile nicht, holt es den Zuwachs beim nächsten Lesen nach –
// verloren geht nur, was vor einem Router-Neustart nicht mehr gelesen wurde.

type DayUse struct {
	RX    uint64 `json:"rx"`     // Download über die Leitung (WAN)
	TX    uint64 `json:"tx"`     // Upload über die Leitung (WAN)
	VPNRX uint64 `json:"vpn_rx"` // davon durch Tunnel (WireGuard, Nutzdaten)
	VPNTX uint64 `json:"vpn_tx"`
}

type ctrState struct {
	Boot int64  `json:"boot"`
	RX   uint64 `json:"rx"`
	TX   uint64 `json:"tx"`
	T    int64  `json:"t"`
}

type trafficFile struct {
	Days  map[string]*DayUse   `json:"tage"`
	WAN   *ctrState            `json:"wan,omitempty"`
	WG    map[string]*ctrState `json:"wg,omitempty"` // iface|pubkey
	Gaps  int                  `json:"luecken"`      // Router-Neustarts, bei denen ein Teil fehlen kann
	Since int64                `json:"seit"`
}

type Traffic struct {
	app  *App
	mu   sync.Mutex
	file string
	d    trafficFile
	// Plausibilität: Zählt die WAN-Schnittstelle weniger als die Tunnel?
	// (Hardware-Beschleunigung kann Pakete am Zähler vorbeischleusen.)
	chkWAN, chkWG uint64
	suspect       bool
	dirty         bool
	lastSave      time.Time
}

func newTraffic(a *App, file string) *Traffic {
	t := &Traffic{app: a, file: file}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &t.d)
	}
	if t.d.Days == nil {
		t.d.Days = map[string]*DayUse{}
	}
	if t.d.WG == nil {
		t.d.WG = map[string]*ctrState{}
	}
	return t
}

func dayKey(t time.Time) string { return t.Format("2006-01-02") }

// spread verteilt einen Zuwachs gleichmäßig über die Tage zwischen from und to.
func spread(days map[string]*DayUse, from, to time.Time, add func(d *DayUse, v uint64), total uint64) {
	if !to.After(from) || to.Sub(from) < time.Hour || dayKey(from) == dayKey(to) {
		d := days[dayKey(to)]
		if d == nil {
			d = &DayUse{}
			days[dayKey(to)] = d
		}
		add(d, total)
		return
	}
	dur := to.Sub(from).Seconds()
	var given uint64
	cur := from
	for cur.Before(to) {
		next := time.Date(cur.Year(), cur.Month(), cur.Day()+1, 0, 0, 0, 0, cur.Location())
		if next.After(to) {
			next = to
		}
		part := uint64(float64(total) * next.Sub(cur).Seconds() / dur)
		if !next.Before(to) {
			part = total - given
		}
		given += part
		d := days[dayKey(cur)]
		if d == nil {
			d = &DayUse{}
			days[dayKey(cur)] = d
		}
		add(d, part)
		cur = next
	}
}

// delta berechnet den Zuwachs eines Zählers seit dem letzten Lesen.
// reboot=true: Zähler wurde zurückgesetzt, es fehlt evtl. etwas.
func delta(prev *ctrState, boot int64, rx, tx uint64) (drx, dtx uint64, reboot bool) {
	if prev == nil {
		return 0, 0, false
	}
	if prev.Boot == boot && rx >= prev.RX && tx >= prev.TX {
		return rx - prev.RX, tx - prev.TX, false
	}
	return rx, tx, prev.Boot != boot
}

// Observe übernimmt die Zählerstände aus einer Router-Abfrage.
func (t *Traffic) Observe(inf RouterInfo, now time.Time) {
	if !inf.HaveWANCt || inf.BootTime == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.d.Since == 0 {
		t.d.Since = now.Unix()
	}
	firstRun := t.d.WAN == nil
	var from time.Time
	if t.d.WAN != nil {
		from = time.Unix(t.d.WAN.T, 0)
	}
	if b := time.Unix(inf.BootTime, 0); t.d.WAN != nil && t.d.WAN.Boot != inf.BootTime && b.After(from) {
		from = b
	}
	drx, dtx, reboot := delta(t.d.WAN, inf.BootTime, inf.WANRX, inf.WANTX)
	if reboot {
		t.d.Gaps++
	}
	if drx+dtx > 0 {
		spread(t.d.Days, from, now, func(d *DayUse, v uint64) { d.RX += v }, drx)
		spread(t.d.Days, from, now, func(d *DayUse, v uint64) { d.TX += v }, dtx)
	}
	t.d.WAN = &ctrState{Boot: inf.BootTime, RX: inf.WANRX, TX: inf.WANTX, T: now.Unix()}
	t.chkWAN += drx

	seen := map[string]bool{}
	for _, tn := range inf.Tunnels {
		k := tn.Iface + "|" + tn.PubKey
		seen[k] = true
		prev := t.d.WG[k]
		var f time.Time
		if prev != nil {
			f = time.Unix(prev.T, 0)
		}
		vrx, vtx, _ := delta(prev, inf.BootTime, tn.RX, tn.TX)
		if prev == nil && !firstRun {
			// neuer Server im Tunnel: Zähler startet beim Wechsel neu
			vrx, vtx, f = tn.RX, tn.TX, now
		}
		if vrx+vtx > 0 {
			spread(t.d.Days, f, now, func(d *DayUse, v uint64) { d.VPNRX += v }, vrx)
			spread(t.d.Days, f, now, func(d *DayUse, v uint64) { d.VPNTX += v }, vtx)
		}
		t.d.WG[k] = &ctrState{Boot: inf.BootTime, RX: tn.RX, TX: tn.TX, T: now.Unix()}
		t.chkWG += vrx
	}
	for k := range t.d.WG {
		if !seen[k] {
			delete(t.d.WG, k)
		}
	}
	// Plausibilität nach mindestens 200 MB Tunnelverkehr
	if t.chkWG > 200<<20 {
		t.suspect = float64(t.chkWAN) < 0.8*float64(t.chkWG)
		t.chkWAN, t.chkWG = 0, 0
	}
	// alte Tage entfernen (13 Monate behalten)
	cut := dayKey(now.AddDate(0, -13, 0))
	for k := range t.d.Days {
		if k < cut {
			delete(t.d.Days, k)
		}
	}
	t.dirty = true
	if time.Since(t.lastSave) > 2*time.Minute {
		t.saveLocked()
	}
}

func (t *Traffic) saveLocked() {
	if !t.dirty {
		return
	}
	b, err := json.Marshal(t.d)
	if err != nil {
		return
	}
	writeAtomic(t.file, b)
	t.dirty, t.lastSave = false, time.Now()
}

func (t *Traffic) Save() {
	t.mu.Lock()
	t.saveLocked()
	t.mu.Unlock()
}

type UsageSum struct {
	RX    uint64 `json:"rx"`
	TX    uint64 `json:"tx"`
	VPNRX uint64 `json:"vpn_rx"`
	VPNTX uint64 `json:"vpn_tx"`
}

func (u *UsageSum) add(d *DayUse) {
	u.RX += d.RX
	u.TX += d.TX
	u.VPNRX += d.VPNRX
	u.VPNTX += d.VPNTX
}

type UsageDay struct {
	Day string `json:"day"`
	DayUse
}

type UsageState struct {
	Today     UsageSum   `json:"today"`
	Month     UsageSum   `json:"month"`
	PrevMonth UsageSum   `json:"prev_month"`
	Forecast  uint64     `json:"forecast"` // hochgerechnet (RX+TX) bis Monatsende
	Days      []UsageDay `json:"days"`     // aktueller Monat
	Since     int64      `json:"since"`
	Gaps      int        `json:"gaps"`
	Suspect   bool       `json:"counter_suspect"`
	HaveCt    bool       `json:"have_counter"`
}

func (t *Traffic) State(now time.Time) UsageState {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := UsageState{Since: t.d.Since, Gaps: t.d.Gaps, Suspect: t.suspect, HaveCt: t.d.WAN != nil}
	mk := now.Format("2006-01")
	pk := now.AddDate(0, 0, -now.Day()).Format("2006-01")
	today := dayKey(now)
	for k, d := range t.d.Days {
		switch {
		case strings.HasPrefix(k, mk):
			st.Month.add(d)
			st.Days = append(st.Days, UsageDay{Day: k, DayUse: *d})
			if k == today {
				st.Today.add(d)
			}
		case strings.HasPrefix(k, pk):
			st.PrevMonth.add(d)
		}
	}
	sort.Slice(st.Days, func(i, j int) bool { return st.Days[i].Day < st.Days[j].Day })
	// Hochrechnung: bisheriger Verbrauch / vergangene Zeit des Monats (ab Messbeginn)
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	if s := time.Unix(t.d.Since, 0); s.After(start) {
		start = s
	}
	end := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
	if el := now.Sub(start).Hours(); el >= 6 {
		total := float64(st.Month.RX + st.Month.TX)
		st.Forecast = uint64(total + total/el*end.Sub(now).Hours())
	}
	return st
}

// ---------- Live-Anzeige ----------

type LiveRate struct {
	T       int64              `json:"t"`
	Down    float64            `json:"down"` // Bit/s über die Leitung
	Up      float64            `json:"up"`
	Tunnels map[string]float64 `json:"tunnels"` // iface -> Down Bit/s
	TunUp   map[string]float64 `json:"tunnels_up"`
}

const liveScript = `W='%s'
while :; do
  [ -n "$W" ] && sed -n "s/^ *$W: *//p" /proc/net/dev | awk '{print "N", $1, $9}'
  wg show all transfer 2>/dev/null | awk '{print "G", $1, $3, $4}'
  echo "T $(cut -d' ' -f1 /proc/uptime)"
  sleep 1
done
`

// RunLive liest die Zähler jede Sekunde, solange eine Oberfläche offen ist.
func (t *Traffic) RunLive() {
	a := t.app
	for !a.quitting() {
		time.Sleep(2 * time.Second)
		ok, _, inf := a.router.State()
		if !ok || !reIface.MatchString(inf.WAN) || !a.hasClients() {
			continue
		}
		t.liveSession(inf.WAN)
	}
}

func (a *App) hasClients() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.clients) > 0
}

func (t *Traffic) liveSession(wan string) {
	a := t.app
	s, err := a.router.Session()
	if err != nil {
		return
	}
	defer s.Close()
	s.Stdin = strings.NewReader(fmt.Sprintf(liveScript, wan))
	out, err := s.StdoutPipe()
	if err != nil {
		return
	}
	if err := s.Start("sh -s"); err != nil {
		return
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		// beenden, wenn niemand mehr zuschaut
		idle := 0
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Second):
			}
			if a.hasClients() {
				idle = 0
			} else if idle++; idle >= 2 || a.quitting() {
				s.Close()
				return
			}
		}
	}()
	sc := bufio.NewScanner(out)
	var prevT, curT float64
	var prevN, curN [2]uint64
	prevG, curG := map[string][2]uint64{}, map[string][2]uint64{}
	haveN := false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) == 3 && f[0] == "N":
			curN[0], _ = strconv.ParseUint(f[1], 10, 64)
			curN[1], _ = strconv.ParseUint(f[2], 10, 64)
			haveN = true
		case len(f) == 4 && f[0] == "G":
			rx, _ := strconv.ParseUint(f[2], 10, 64)
			tx, _ := strconv.ParseUint(f[3], 10, 64)
			v := curG[f[1]]
			curG[f[1]] = [2]uint64{v[0] + rx, v[1] + tx}
		case len(f) == 2 && f[0] == "T":
			curT, _ = strconv.ParseFloat(f[1], 64)
			if prevT > 0 && curT > prevT && haveN {
				dt := curT - prevT
				lr := LiveRate{T: time.Now().UnixMilli(), Tunnels: map[string]float64{}, TunUp: map[string]float64{}}
				if curN[0] >= prevN[0] && curN[1] >= prevN[1] {
					lr.Down = float64(curN[0]-prevN[0]) * 8 / dt
					lr.Up = float64(curN[1]-prevN[1]) * 8 / dt
				}
				for k, v := range curG {
					if p, ok := prevG[k]; ok && v[0] >= p[0] && v[1] >= p[1] {
						lr.Tunnels[k] = float64(v[0]-p[0]) * 8 / dt
						lr.TunUp[k] = float64(v[1]-p[1]) * 8 / dt
					}
				}
				a.broadcast("live", lr)
			}
			prevT, prevN, prevG = curT, curN, curG
			curG = map[string][2]uint64{}
			haveN = false
		}
	}
}

// ---------- Verbrauch je Gerät (GL.iNet-Geräteliste) ----------

type Device struct {
	Name   string `json:"name"`
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Online bool   `json:"online"`
	RX     uint64 `json:"rx"` // Download des Geräts (Bytes, laut Router)
	TX     uint64 `json:"tx"`
	RXRate uint64 `json:"rx_rate"`
	TXRate uint64 `json:"tx_rate"`
}

func anyStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func anyNum(m map[string]any, keys ...string) (uint64, bool) {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			if v >= 0 {
				return uint64(v), true
			}
		case string:
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// parseDevices wertet clients.get_list aus. Die Feldnamen unterscheiden sich
// je nach Firmware, deshalb werden mehrere Varianten geprüft.
func parseDevices(raw json.RawMessage) ([]Device, bool) {
	var res struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		var list []map[string]any
		if json.Unmarshal(raw, &list) != nil {
			return nil, false
		}
		res.Clients = list
	}
	haveTraffic := false
	var out []Device
	for _, c := range res.Clients {
		d := Device{
			Name: anyStr(c, "alias", "name", "hostname"),
			MAC:  strings.ToLower(anyStr(c, "mac")),
			IP:   anyStr(c, "ip", "ipv4"),
		}
		if v, ok := c["online"].(bool); ok {
			d.Online = v
		}
		if v, ok := anyNum(c, "total_rx", "rx_total", "total_down", "download_total"); ok {
			d.RX, haveTraffic = v, true
		}
		if v, ok := anyNum(c, "total_tx", "tx_total", "total_up", "upload_total"); ok {
			d.TX, haveTraffic = v, true
		}
		d.RXRate, _ = anyNum(c, "rx", "rx_speed", "down_speed")
		d.TXRate, _ = anyNum(c, "tx", "tx_speed", "up_speed")
		if d.Name == "" {
			d.Name = d.MAC
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RX+out[i].TX > out[j].RX+out[j].TX })
	return out, haveTraffic
}

func (a *App) Devices() ([]Device, bool, error) {
	if a.router.isNative() {
		return nil, false, errors.New(a.tr("Die Geräteliste mit Datenmengen gibt es nur bei GL.iNet-Routern.", "The device list with data volumes is only available on GL.iNet routers."))
	}
	var raw json.RawMessage
	if err := a.router.RPC("clients", "get_list", map[string]any{}, &raw); err != nil {
		return nil, false, err
	}
	d, ok := parseDevices(raw)
	return d, ok, nil
}

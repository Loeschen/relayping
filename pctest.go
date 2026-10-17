package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PC-Speedtest: RelayPing lädt auf dem PC selbst – also genau über den Weg,
// den auch dein Internet nimmt (PC → Router → Tunnel). Gleichzeitig pingt der
// Router durch denselben Tunnel das Mullvad-Gateway. So entsteht der Wert
// „Ping unter Last“ (Bufferbloat).

var (
	pcDownURL = envOr("RELAYPING_SPEED_DOWN", "https://speed.cloudflare.com/__down?bytes=50000000")
	pcUpURL   = envOr("RELAYPING_SPEED_UP", "https://speed.cloudflare.com/__up")
)

const (
	pcStreams  = 6
	pcIdleSecs = 5
	pcDownSecs = 10
	pcUpSecs   = 8
)

type PingStats struct {
	N      int     `json:"n"`
	Median float64 `json:"median"`
	P95    float64 `json:"p95"`
	Loss   float64 `json:"loss"`
}

type PCTest struct {
	Running   bool      `json:"running"`
	Stage     string    `json:"stage"` // leerlauf, download, upload, fertig
	Mbps      float64   `json:"mbps"`  // laufender Wert
	Down      float64   `json:"down"`
	Up        float64   `json:"up"`
	Idle      PingStats `json:"idle"`
	LoadDown  PingStats `json:"load_down"`
	LoadUp    PingStats `json:"load_up"`
	Grade     string    `json:"grade"` // A–D
	Tunnel    string    `json:"tunnel"`
	Host      string    `json:"host"`
	Error     string    `json:"error,omitempty"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
	Bytes     int64     `json:"bytes"`
	PingNote  string    `json:"ping_note,omitempty"`
	Elapsed   float64   `json:"elapsed"`
	StageSecs int       `json:"stage_secs"`
}

type PCTester struct {
	app  *App
	mu   sync.Mutex
	st   PCTest
	last PCTest
	hist []PCTest
	file string
}

func newPCTester(a *App, file string) *PCTester {
	p := &PCTester{app: a, file: file}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &p.hist)
	}
	if n := len(p.hist); n > 0 {
		p.last = p.hist[n-1]
	}
	return p
}

func (p *PCTester) History() []PCTest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]PCTest(nil), p.hist...)
}

func (p *PCTester) State() PCTest {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st.Running {
		return p.st
	}
	return p.last
}

func (p *PCTester) set(fn func(t *PCTest)) {
	p.mu.Lock()
	fn(&p.st)
	st := p.st
	p.mu.Unlock()
	p.app.broadcast("pctest", st)
}

// defaultTunnel: der Tunnel, über den der normale Verkehr läuft (Ziel „alle“).
func (a *App) defaultTunnel() (Tunnel, bool) {
	_, _, inf := a.router.State()
	gl := a.router.GL()
	if gl != nil {
		for _, g := range gl.Tunnels {
			to, _ := g.Raw["to"].(map[string]any)
			if to != nil && to["type"] == "default" {
				for _, t := range inf.Tunnels {
					if t.Iface == g.Iface {
						return t, true
					}
				}
			}
		}
	}
	for _, t := range inf.Tunnels {
		if inf.DefIface != "" && t.Iface == inf.DefIface {
			return t, true
		}
	}
	if len(inf.Tunnels) == 1 {
		return inf.Tunnels[0], true
	}
	return Tunnel{}, false
}

func (p *PCTester) Start() error {
	a := p.app
	p.mu.Lock()
	if p.st.Running {
		p.mu.Unlock()
		return errors.New(a.tr("Es läuft bereits ein Test", "A test is already running"))
	}
	if a.speed.Running() || a.switcher.Status().Running {
		p.mu.Unlock()
		return errors.New(a.tr("Gerade läuft ein Speedtest oder Server-Wechsel", "A speed test or server switch is running"))
	}
	p.st = PCTest{Running: true, Stage: "leerlauf", Started: time.Now(), StageSecs: pcIdleSecs}
	p.mu.Unlock()
	go p.run()
	return nil
}

type pingSample struct {
	at time.Time
	ms float64 // < 0 verloren
}

// pingLoop pingt durch den Tunnel (5 pro Sekunde), bis ctx endet.
func (p *PCTester) pingLoop(ctx context.Context, iface string, out *[]pingSample, mu *sync.Mutex) error {
	a := p.app
	if !reIface.MatchString(iface) {
		return errors.New("iface")
	}
	s, err := a.router.Session()
	if err != nil {
		return err
	}
	defer s.Close()
	pipe, err := s.StdoutPipe()
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(`O="-i 0.2"; ping -c 1 -i 0.2 127.0.0.1 >/dev/null 2>&1 || O=""; exec ping $O -W 1 -I %s 10.64.0.1`, iface)
	if err := s.Start(cmd); err != nil {
		return err
	}
	go func() { <-ctx.Done(); s.Close() }()
	sc := bufio.NewScanner(pipe)
	lastSeq := -1
	for sc.Scan() {
		m := reReply.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		seq, _ := strconv.Atoi(m[1])
		ms, _ := strconv.ParseFloat(m[2], 64)
		now := time.Now()
		mu.Lock()
		for lastSeq >= 0 && seq > lastSeq+1 { // fehlende Antworten = verloren
			*out = append(*out, pingSample{at: now, ms: -1})
			lastSeq++
		}
		*out = append(*out, pingSample{at: now, ms: ms})
		mu.Unlock()
		lastSeq = seq
	}
	return nil
}

func statsBetween(s []pingSample, from, to time.Time) PingStats {
	var v []float64
	n := 0
	for _, x := range s {
		if x.at.Before(from) || x.at.After(to) {
			continue
		}
		n++
		if x.ms >= 0 {
			v = append(v, x.ms)
		}
	}
	st := PingStats{N: n}
	if n > 0 {
		st.Loss = round1(float64(n-len(v)) * 100 / float64(n))
	}
	if len(v) > 0 {
		sort.Float64s(v)
		st.Median = round1(median(v))
		st.P95 = round1(v[int(float64(len(v)-1)*0.95)])
	}
	return st
}

// bufferGrade: Anstieg des Pings unter Last gegenüber Leerlauf.
func bufferGrade(idle, down, up PingStats) string {
	if idle.N == 0 || idle.Median == 0 {
		return ""
	}
	inc := 0.0
	for _, s := range []PingStats{down, up} {
		if s.Median > 0 && s.Median-idle.Median > inc {
			inc = s.Median - idle.Median
		}
	}
	switch {
	case inc < 5:
		return "A"
	case inc < 30:
		return "B"
	case inc < 60:
		return "C"
	}
	return "D"
}

type countWriter struct{ n *int64 }

func (c countWriter) Write(b []byte) (int, error) {
	atomic.AddInt64(c.n, int64(len(b)))
	return len(b), nil
}

type zeroReader struct {
	left int64
	n    *int64
}

func (z *zeroReader) Read(b []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > z.left {
		b = b[:z.left]
	}
	for i := range b {
		b[i] = 0
	}
	z.left -= int64(len(b))
	atomic.AddInt64(z.n, int64(len(b)))
	return len(b), nil
}

// transfer lädt (down=true) oder sendet für secs Sekunden mit mehreren
// Verbindungen und meldet laufend den Zwischenstand. Auch abgebrochene
// Übertragungen zählen mit.
func (p *PCTester) transfer(down bool, secs int) (float64, int64) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	client := &http.Client{}
	var total int64
	var wg sync.WaitGroup
	for i := 0; i < pcStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				var req *http.Request
				if down {
					req, _ = http.NewRequestWithContext(ctx, http.MethodGet, pcDownURL, nil)
				} else {
					req, _ = http.NewRequestWithContext(ctx, http.MethodPost, pcUpURL, &zeroReader{left: 25 << 20, n: &total})
					req.ContentLength = 25 << 20
					req.Header.Set("Content-Type", "application/octet-stream")
				}
				req.Header.Set("User-Agent", "RelayPing/"+version)
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						time.Sleep(300 * time.Millisecond)
					}
					continue
				}
				if down {
					_, _ = io.Copy(countWriter{&total}, resp.Body)
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
				resp.Body.Close()
			}
		}()
	}
	start := time.Now()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	for {
		select {
		case <-finished:
			el := time.Since(start).Seconds()
			n := atomic.LoadInt64(&total)
			if el <= 0 {
				return 0, n
			}
			return round1(float64(n) * 8 / el / 1e6), n
		case <-tick.C:
			el := time.Since(start).Seconds()
			if el > 0.5 {
				mbps := round1(float64(atomic.LoadInt64(&total)) * 8 / el / 1e6)
				p.set(func(t *PCTest) { t.Mbps, t.Elapsed = mbps, round1(el) })
			}
		}
	}
}

func (p *PCTester) run() {
	a := p.app
	tn, haveTun := a.defaultTunnel()
	var samples []pingSample
	var smu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	pingNote := ""
	if haveTun {
		p.set(func(t *PCTest) {
			t.Tunnel, t.Host = tn.Name, tn.Host
			if t.Tunnel == "" {
				t.Tunnel = tn.Iface
			}
		})
		go func() {
			if err := p.pingLoop(ctx, tn.Iface, &samples, &smu); err != nil {
				pingNote = err.Error()
			}
		}()
	} else {
		pingNote = a.tr("Kein Standard-Tunnel erkannt – Ping unter Last nicht messbar", "No default tunnel found – loaded ping not measurable")
	}
	t0 := time.Now()
	time.Sleep(pcIdleSecs * time.Second)
	t1 := time.Now()
	p.set(func(t *PCTest) { t.Stage, t.Mbps, t.Elapsed, t.StageSecs = "download", 0, 0, pcDownSecs })
	down, nDown := p.transfer(true, pcDownSecs)
	t2 := time.Now()
	p.set(func(t *PCTest) { t.Stage, t.Down, t.Mbps, t.Elapsed, t.StageSecs = "upload", down, 0, 0, pcUpSecs })
	up, nUp := p.transfer(false, pcUpSecs)
	t3 := time.Now()
	time.Sleep(500 * time.Millisecond)
	cancel()
	smu.Lock()
	idle := statsBetween(samples, t0.Add(time.Second), t1)
	ld := statsBetween(samples, t1.Add(2*time.Second), t2)
	lu := statsBetween(samples, t2.Add(2*time.Second), t3)
	smu.Unlock()
	p.mu.Lock()
	p.st.Running, p.st.Stage, p.st.Finished = false, "fertig", time.Now()
	p.st.Down, p.st.Up, p.st.Mbps = down, up, 0
	p.st.Idle, p.st.LoadDown, p.st.LoadUp = idle, ld, lu
	p.st.Grade = bufferGrade(idle, ld, lu)
	p.st.Bytes = nDown + nUp
	p.st.PingNote = pingNote
	if nDown == 0 && nUp == 0 {
		p.st.Error = a.tr("Keine Verbindung zum Testserver (speed.cloudflare.com)", "No connection to the test server (speed.cloudflare.com)")
	}
	p.last = p.st
	st := p.st
	if st.Error == "" {
		p.hist = append(p.hist, st)
		if len(p.hist) > 200 {
			p.hist = p.hist[len(p.hist)-200:]
		}
		if b, err := json.Marshal(p.hist); err == nil && p.file != "" {
			writeAtomic(p.file, b)
		}
	}
	p.mu.Unlock()
	a.broadcast("pctest", st)
	if st.Error == "" {
		a.csv.PCTest(st)
		msg := fmt.Sprintf(a.tr("PC-Speedtest: ↓ %.0f Mbit/s, ↑ %.0f Mbit/s", "PC speed test: ↓ %.0f Mbit/s, ↑ %.0f Mbit/s"), st.Down, st.Up)
		if st.Grade != "" {
			msg += fmt.Sprintf(a.tr(", Ping %.0f → %.0f ms unter Last (%s)", ", ping %.0f → %.0f ms under load (%s)"), st.Idle.Median, maxF(st.LoadDown.Median, st.LoadUp.Median), st.Grade)
		}
		a.log.Printf("%s", msg)
		a.day.Event("speedtest", msg)
	}
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func (c *CSVLog) PCTest(t PCTest) {
	line := fmt.Sprintf("%s;%s;%s;%s;%s;%s;%s;%s", t.Finished.Format("02.01.2006 15:04:05"), t.Host, de(t.Down), de(t.Up),
		de(t.Idle.Median), de(t.LoadDown.Median), de(t.LoadUp.Median), t.Grade)
	c.write("pc-speedtest.csv", "Zeitpunkt;Server;Download Mbit/s;Upload Mbit/s;Ping Leerlauf ms;Ping Download ms;Ping Upload ms;Bewertung", []string{line})
}

// ---------- DNS-Leck-Test ----------

type LeakResult struct {
	Exit     bool     `json:"mullvad_exit"`
	ExitHost string   `json:"exit_host"`
	IP       string   `json:"ip"`
	City     string   `json:"city"`
	Country  string   `json:"country"`
	Org      string   `json:"org"`
	Listed   bool     `json:"blacklisted"`
	DNS      []string `json:"dns"`
	DNSLeak  bool     `json:"dns_leak"`
	DNSOK    bool     `json:"dns_checked"`
	Error    string   `json:"error,omitempty"`
	Checked  int64    `json:"checked"`
	// Woher kommen die DNS-Antworten?
	DNSHost     string   `json:"dns_host,omitempty"`
	DNSTunnel   string   `json:"dns_tunnel,omitempty"`
	TrafficHost string   `json:"traffic_host,omitempty"`
	Upstreams   []string `json:"upstreams,omitempty"`
	DNSOther    bool     `json:"dns_other_tunnel"`
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LeakCheck nutzt Mullvads eigene Verbindungsprüfung (am.i.mullvad.net) vom
// PC aus – also über denselben Weg und denselben DNS wie dein Browser.
func (a *App) LeakCheck() LeakResult {
	res := LeakResult{Checked: time.Now().Unix()}
	cl := &http.Client{Timeout: 12 * time.Second}
	get := func(u string) ([]byte, error) {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "RelayPing/"+version)
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode != 200 {
			return b, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return b, err
	}
	if b, err := get("https://ipv4.am.i.mullvad.net/json"); err == nil {
		var j struct {
			IP       string `json:"ip"`
			Country  string `json:"country"`
			City     string `json:"city"`
			Exit     bool   `json:"mullvad_exit_ip"`
			ExitHost string `json:"mullvad_exit_ip_hostname"`
			Org      string `json:"organization"`
			Black    struct {
				Blacklisted bool `json:"blacklisted"`
			} `json:"blacklisted"`
		}
		if json.Unmarshal(b, &j) == nil {
			res.IP, res.Country, res.City, res.Exit, res.ExitHost, res.Org, res.Listed = j.IP, j.Country, j.City, j.Exit, j.ExitHost, j.Org, j.Black.Blacklisted
		}
	} else {
		res.Error = err.Error()
		return res
	}
	domain := "dnsleak.am.i.mullvad.net"
	if b, err := get("https://am.i.mullvad.net/config"); err == nil {
		var c struct {
			D string `json:"dns_leak_domain"`
		}
		if json.Unmarshal(b, &c) == nil && cleanDomain(c.D) != "" {
			domain = c.D
		}
	}
	seen := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := get("https://" + randHex(16) + "." + domain + "/")
			if err != nil {
				return
			}
			txt := strings.TrimSpace(string(b))
			if len(txt) > 200 {
				txt = txt[:200]
			}
			mu.Lock()
			seen[txt] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	for t := range seen {
		res.DNS = append(res.DNS, t)
		res.DNSOK = true
		if !strings.Contains(strings.ToLower(t), "you are using mullvad dns") {
			res.DNSLeak = true
		}
	}
	sort.Strings(res.DNS)
	// Mullvad nennt den antwortenden Server: "… (server se-mma-wg-003, Malmö, Sweden)"
	for _, t := range res.DNS {
		if i := strings.Index(t, "server "); i >= 0 {
			h := strings.Fields(strings.TrimRight(t[i+7:], ")."))
			if len(h) > 0 {
				res.DNSHost = strings.TrimRight(h[0], ",")
			}
		}
	}
	if tn, ok := a.defaultTunnel(); ok {
		res.TrafficHost = tn.Host
	}
	// Router: über welchen Tunnel geht 10.64.0.1, welche Upstreams nutzt AdGuard Home?
	out, err := a.router.Run(`echo "ROUTE $(ip route get 10.64.0.1 2>/dev/null | head -1)"
F=/etc/AdGuardHome/config.yaml; [ -r "$F" ] || F=$(ls /etc/AdGuardHome/*.yaml 2>/dev/null | head -1)
[ -n "$F" ] && awk '/^ *upstream_dns:/{f=1; next} f && /^ *- /{sub(/^ *- */,""); print "UP " $0; next} f{exit}' "$F" 2>/dev/null`, 10*time.Second)
	if err == nil || out != "" {
		_, _, inf := a.router.State()
		for _, l := range strings.Split(out, "\n") {
			switch {
			case strings.HasPrefix(l, "ROUTE "):
				f := strings.Fields(l)
				for i := 0; i+1 < len(f); i++ {
					if f[i] == "dev" {
						res.DNSTunnel = f[i+1]
						for _, t := range inf.Tunnels {
							if t.Iface == f[i+1] && t.Name != "" {
								res.DNSTunnel = t.Name + " (" + t.Iface + ")"
							}
						}
					}
				}
			case strings.HasPrefix(l, "UP "):
				u := strings.Trim(strings.TrimSpace(l[3:]), `"'`)
				if u != "" && len(res.Upstreams) < 8 {
					res.Upstreams = append(res.Upstreams, u)
				}
			}
		}
	}
	res.DNSOther = res.DNSHost != "" && res.TrafficHost != "" && res.DNSHost != res.TrafficHost
	return res
}

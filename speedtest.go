package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Speedtest: Der Router lädt einige Sekunden lang über mehrere parallele
// Verbindungen eine Testdatei von Cloudflare herunter – einmal durch den Tunnel
// (also über den aktiven Mullvad-Server) und zum Vergleich über die WAN-Leitung.
// Ergebnis ist eine Größenordnung: Die Router-CPU (TLS, WireGuard) begrenzt mit.

const (
	speedSecs    = 10
	speedStreams = 4
	speedURL     = "https://speed.cloudflare.com/__down?bytes=25000000"
)

type SpeedResult struct {
	T       time.Time `json:"t"`
	Host    string    `json:"host"`
	Iface   string    `json:"iface"`
	Mbps    float64   `json:"mbps"`
	WanMbps float64   `json:"wan_mbps"`
}

type SpeedState struct {
	Running  bool                   `json:"running"`
	Iface    string                 `json:"iface"`
	Host     string                 `json:"host"`
	Stage    string                 `json:"stage"` // tunnel, wan
	Mbps     float64                `json:"mbps"`  // laufender Wert der aktuellen Stufe
	Elapsed  float64                `json:"elapsed"`
	Secs     int                    `json:"secs"`
	Error    string                 `json:"error,omitempty"`
	Started  time.Time              `json:"started"`
	Finished time.Time              `json:"finished"`
	Results  map[string]SpeedResult `json:"results"` // je Server das letzte Ergebnis
}

type Speed struct {
	app  *App
	mu   sync.Mutex
	st   SpeedState
	file string
}

func newSpeed(a *App, file string) *Speed {
	s := &Speed{app: a, file: file, st: SpeedState{Secs: speedSecs, Results: map[string]SpeedResult{}}}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &s.st.Results)
	}
	if s.st.Results == nil {
		s.st.Results = map[string]SpeedResult{}
	}
	return s
}

func (s *Speed) State() SpeedState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Results = make(map[string]SpeedResult, len(s.st.Results))
	for k, v := range s.st.Results {
		st.Results[k] = v
	}
	return st
}

// Busy: Test läuft oder ist weniger als 3 Minuten her – dann sind Latenzwerte
// verfälscht (volle Leitung) und Warnungen werden ausgesetzt.
func (s *Speed) Busy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Running || (!s.st.Finished.IsZero() && time.Since(s.st.Finished) < 3*time.Minute)
}

func (s *Speed) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Running
}

func (s *Speed) push() { s.app.broadcast("speed", s.State()) }

func (s *Speed) Start(iface string) error {
	a := s.app
	if !reIface.MatchString(iface) {
		return errors.New(a.tr("Ungültige Schnittstelle", "Invalid interface"))
	}
	ok, _, inf := a.router.State()
	if !ok {
		return a.router.notConnected()
	}
	var tun *Tunnel
	for i := range inf.Tunnels {
		if inf.Tunnels[i].Iface == iface {
			tun = &inf.Tunnels[i]
		}
	}
	if tun == nil {
		return errors.New(a.tr("Dieser Tunnel ist gerade nicht aktiv", "This tunnel is not active right now"))
	}
	if a.switcher.Status().Running {
		return errors.New(a.tr("Gerade läuft ein Server-Wechsel", "A server switch is running"))
	}
	s.mu.Lock()
	if s.st.Running {
		s.mu.Unlock()
		return errors.New(a.tr("Es läuft bereits ein Speedtest", "A speed test is already running"))
	}
	s.st.Running, s.st.Iface, s.st.Host, s.st.Stage = true, iface, tun.Host, "tunnel"
	s.st.Mbps, s.st.Elapsed, s.st.Error, s.st.Started = 0, 0, "", time.Now()
	s.mu.Unlock()
	s.push()
	go s.run(iface, tun.Host, inf.WAN)
	return nil
}

func (s *Speed) run(iface, host, wan string) {
	a := s.app
	res := SpeedResult{T: time.Now(), Host: host, Iface: iface}
	mbps, err := s.measure(iface)
	if err == nil {
		res.Mbps = mbps
		if reIface.MatchString(wan) {
			s.mu.Lock()
			s.st.Stage, s.st.Mbps, s.st.Elapsed = "wan", 0, 0
			s.mu.Unlock()
			s.push()
			if w, werr := s.measure(wan); werr == nil {
				res.WanMbps = w
			}
		}
	}
	s.mu.Lock()
	s.st.Running, s.st.Finished = false, time.Now()
	if err != nil {
		s.st.Error = err.Error()
	} else {
		s.st.Error = ""
		s.st.Mbps = res.Mbps
		if host != "" {
			s.st.Results[host] = res
		}
	}
	b, _ := json.MarshalIndent(s.st.Results, "", "  ")
	s.mu.Unlock()
	if err == nil {
		_ = os.WriteFile(s.file, b, 0o600)
		a.csv.Speed(res)
		msg := fmt.Sprintf(a.tr("%s: ca. %.0f Mbit/s über den Tunnel", "%s: about %.0f Mbit/s through the tunnel"), host, res.Mbps)
		if res.WanMbps > 0 {
			msg += fmt.Sprintf(a.tr(" (Leitung ohne VPN: %.0f Mbit/s)", " (line without VPN: %.0f Mbit/s)"), res.WanMbps)
		}
		a.log.Printf("Speedtest %s", msg)
	} else {
		a.log.Printf("Speedtest %s fehlgeschlagen: %v", iface, err)
	}
	s.push()
}

const speedScript = `IF='%s'; T=%d; N=%d; U='%s'
command -v curl >/dev/null 2>&1 || { echo "ERR nocurl"; exit 0; }
end=$(( $(date +%%s) + T ))
echo START
one() {
  while :; do
    r=$(( end - $(date +%%s) )); [ $r -lt 1 ] && break
    curl -s -o /dev/null --interface "$IF" -m $r -w 'S %%{size_download} %%{http_code}\n' "$U" 2>/dev/null
    rc=$?; [ $rc -eq 0 ] || [ $rc -eq 28 ] || sleep 1
  done
}
i=0; while [ $i -lt $N ]; do one & i=$((i+1)); done
wait; echo DONE
`

// measure lädt speedSecs Sekunden lang über die Schnittstelle und liefert Mbit/s.
func (s *Speed) measure(iface string) (float64, error) {
	a := s.app
	sess, err := a.router.Session()
	if err != nil {
		return 0, err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(fmt.Sprintf(speedScript, iface, speedSecs, speedStreams, speedURL))
	out, err := sess.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := sess.Start("sh -s"); err != nil {
		return 0, err
	}
	start := time.Now()
	var total float64
	ok200 := false
	lastPush := time.Now()
	sc := bufio.NewScanner(out)
	timeout := time.AfterFunc(time.Duration(speedSecs+25)*time.Second, func() { sess.Close() })
	defer timeout.Stop()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 1 && f[0] == "START" {
			start = time.Now() // ab hier läuft die Messung auf dem Router
			continue
		}
		if len(f) == 2 && f[0] == "ERR" {
			return 0, errors.New(a.tr("Auf dem Router fehlt curl", "curl is missing on the router"))
		}
		if len(f) == 3 && f[0] == "S" {
			n, _ := strconv.ParseFloat(f[1], 64)
			total += n
			if f[2] == "200" {
				ok200 = true
			}
			el := time.Since(start).Seconds()
			if time.Since(lastPush) > 700*time.Millisecond && el > 0.5 {
				s.mu.Lock()
				s.st.Mbps, s.st.Elapsed = round1(total*8/el/1e6), round1(el)
				s.mu.Unlock()
				s.push()
				lastPush = time.Now()
			}
		}
		if len(f) == 1 && f[0] == "DONE" {
			break
		}
	}
	if total <= 0 || !ok200 {
		return 0, fmt.Errorf(a.tr("Keine Verbindung zum Testserver über %s", "No connection to the test server via %s"), iface)
	}
	// Bezugszeit: Testdauer (Wanduhr), höchstens etwas über speedSecs
	el := time.Since(start).Seconds()
	if el < speedSecs {
		el = speedSecs
	}
	return round1(total * 8 / el / 1e6), nil
}

// Speed schreibt ein Speedtest-Ergebnis nach verlauf/speedtest.csv.
func (c *CSVLog) Speed(r SpeedResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.MkdirAll(c.dir(), 0o755)
	p := filepath.Join(c.dir(), "speedtest.csv")
	_, statErr := os.Stat(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if os.IsNotExist(statErr) {
		f.WriteString("\xef\xbb\xbfZeitpunkt;Tunnel;Server;Mbit/s Tunnel;Mbit/s ohne VPN\r\n")
	}
	f.WriteString(fmt.Sprintf("%s;%s;%s;%s;%s\r\n", r.T.Format("02.01.2006 15:04:05"), r.Iface, r.Host, de(r.Mbps), de(r.WanMbps)))
}

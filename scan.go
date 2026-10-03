package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Relay
	Loss   int     `json:"loss"`
	Avg    float64 `json:"avg"`
	Jitter float64 `json:"jitter"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Recv   int     `json:"recv"`
	Active bool    `json:"active"`
}

type ScanState struct {
	Running   bool         `json:"running"`
	Done      int          `json:"done"`
	Total     int          `json:"total"`
	Countries []string     `json:"countries"`
	Pings     int          `json:"pings"`
	Started   time.Time    `json:"started"`
	Finished  time.Time    `json:"finished"`
	Error     string       `json:"error,omitempty"`
	Results   []ScanResult `json:"results"`
}

type Scanner struct {
	app    *App
	mu     sync.Mutex
	state  ScanState
	cancel chan struct{}
}

// Das Skript läuft auf dem Router (BusyBox). IPs und Schnittstelle sind vorher geprüft.
const scanScript = `C=%d; W='%s'; P=30
IF=""; [ -n "$W" ] && IF="-I $W"
if ping -c 1 -i 0.2 -W 1 127.0.0.1 >/dev/null 2>&1; then O="-i 0.2"; D=$((C/5+4)); else O=""; D=$((C+4)); fi
one() {
  ping -c $C $O -W 2 -w $D $IF "$1" 2>/dev/null | awk -v ip="$1" -v n=$C '
    /time=/ && !/DUP!/ { t=$0; sub(/.*time=/,"",t); sub(/[ ]*ms.*/,"",t); t+=0; c++; s+=t
      if(c==1||t<mn)mn=t; if(c==1||t>mx)mx=t; if(c>1){d=t-p; if(d<0)d=-d; js+=d; jc++} p=t }
    END { if(c>n)c=n; loss=int((n-c)*100/n+0.5)
      if(c>0) printf "R %%s %%d %%.2f %%.2f %%.2f %%.2f %%d\n", ip, loss, s/c, (jc?js/jc:0), mn, mx, c
      else printf "R %%s 100 0 0 0 0 0\n", ip }'
}
i=0
for ip in %s; do one "$ip" & i=$((i+1)); [ $((i %% P)) -eq 0 ] && wait; done
wait
echo DONE
`

func (s *Scanner) State() ScanState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	st.Results = append([]ScanResult(nil), s.state.Results...)
	return st
}

func (s *Scanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		close(s.cancel)
		s.cancel = nil
	}
}

func (s *Scanner) Start(countries []string, pings int) error {
	if pings < 5 || pings > 100 {
		return errors.New("Pings pro Server: 5 bis 100")
	}
	list := s.app.relays.ByCountries(countries)
	if len(list) == 0 {
		return errors.New("Keine Server für diese Auswahl")
	}
	var ips []string
	byIP := map[string]Relay{}
	for _, r := range list {
		ip := net.ParseIP(r.IPv4)
		if ip == nil || ip.To4() == nil {
			continue
		}
		ips = append(ips, ip.To4().String())
		byIP[ip.To4().String()] = r
	}
	wan := ""
	if _, _, inf := s.app.router.State(); reIface.MatchString(inf.WAN) {
		wan = inf.WAN
	}
	script := fmt.Sprintf(scanScript, pings, wan, strings.Join(ips, " "))

	s.mu.Lock()
	if s.state.Running {
		s.mu.Unlock()
		return errors.New("Es läuft bereits eine Messung")
	}
	cancel := make(chan struct{})
	s.cancel = cancel
	s.state = ScanState{Running: true, Total: len(ips), Countries: countries, Pings: pings, Started: time.Now()}
	s.mu.Unlock()
	s.app.broadcast("scan", s.State())

	go s.run(script, byIP, cancel)
	return nil
}

func (s *Scanner) run(script string, byIP map[string]Relay, cancel chan struct{}) {
	finish := func(errText string) {
		s.mu.Lock()
		s.state.Running = false
		s.state.Finished = time.Now()
		s.state.Error = errText
		if s.cancel == cancel {
			s.cancel = nil
		}
		sortResults(s.state.Results)
		st := s.state
		st.Results = append([]ScanResult(nil), s.state.Results...)
		s.mu.Unlock()
		if errText == "" {
			s.app.csv.Scan(st)
		}
		s.app.broadcast("scan", st)
	}

	sess, err := s.app.router.Session()
	if err != nil {
		finish("Nicht mit dem Router verbunden")
		return
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(script)
	out, err := sess.StdoutPipe()
	if err != nil {
		finish(err.Error())
		return
	}
	if err := sess.Start("sh -s"); err != nil {
		finish(err.Error())
		return
	}
	active := s.app.activeIPs()
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	lastPush := time.Time{}
	for {
		select {
		case <-cancel:
			finish("Abgebrochen")
			return
		case l, ok := <-lines:
			if !ok {
				finish("")
				return
			}
			if l == "DONE" {
				continue
			}
			f := strings.Fields(l)
			if len(f) != 8 || f[0] != "R" {
				continue
			}
			rl, ok := byIP[f[1]]
			if !ok {
				continue
			}
			res := ScanResult{Relay: rl, Active: active[f[1]]}
			res.Loss, _ = strconv.Atoi(f[2])
			res.Avg, _ = strconv.ParseFloat(f[3], 64)
			res.Jitter, _ = strconv.ParseFloat(f[4], 64)
			res.Min, _ = strconv.ParseFloat(f[5], 64)
			res.Max, _ = strconv.ParseFloat(f[6], 64)
			res.Recv, _ = strconv.Atoi(f[7])
			s.mu.Lock()
			s.state.Results = append(s.state.Results, res)
			s.state.Done = len(s.state.Results)
			push := time.Since(lastPush) > 300*time.Millisecond || s.state.Done == s.state.Total
			s.mu.Unlock()
			if push {
				lastPush = time.Now()
				s.app.broadcast("scan", s.State())
			}
		}
	}
}

// Sortierung: erst Paketverlust, dann Mittelwert. Keine Antwort ganz unten.
func sortResults(r []ScanResult) {
	sort.SliceStable(r, func(i, j int) bool {
		a, b := r[i], r[j]
		if (a.Recv == 0) != (b.Recv == 0) {
			return b.Recv == 0
		}
		if a.Loss != b.Loss {
			return a.Loss < b.Loss
		}
		return a.Avg < b.Avg
	})
}

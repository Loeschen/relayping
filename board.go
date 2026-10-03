package main

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Die Bestenliste pingt alle Server der gewählten Länder dauerhaft in Runden
// (Standard: alle 10 s je 3 Pings) und sortiert laufend neu.

const (
	boardKeep   = 60 // Runden im Speicher (bei 10 s = 10 Minuten)
	boardWindow = 6  // Runden für die Bewertung (bei 10 s = 1 Minute)
	boardMax    = 80 // höchstens so viele Server gleichzeitig
	boardPings  = 3
)

type BoardRound struct {
	T    int64   `json:"t"`
	Avg  float64 `json:"avg"`
	Jit  float64 `json:"jit"`
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	Recv int     `json:"recv"`
}

type BoardRow struct {
	Relay
	Now       float64   `json:"now"`       // letzte Runde, -1 = verloren
	Median    float64   `json:"median"`    // Median über das Bewertungsfenster
	Jitter    float64   `json:"jitter"`    // mittlerer Jitter im Fenster
	Loss      float64   `json:"loss"`      // Verlust im Fenster in %
	Spark     []float64 `json:"spark"`     // letzte Runden, -1 = verloren
	Active    bool      `json:"active"`    // von einem Tunnel genutzt
	Stability float64   `json:"stability"` // 0..100, -1 = zu wenig Daten
	Rounds    int       `json:"rounds"`
}

type BoardState struct {
	On        bool       `json:"on"`
	Running   bool       `json:"running"`
	Countries []string   `json:"countries"`
	Interval  int        `json:"interval"`
	Round     int        `json:"round"`
	Updated   time.Time  `json:"updated"`
	Error     string     `json:"error,omitempty"`
	Capped    bool       `json:"capped"`
	Rows      []BoardRow `json:"rows"`
}

type Board struct {
	app      *App
	mu       sync.Mutex
	data     map[string][]BoardRound // host -> Runden
	relays   map[string]Relay        // ip -> Relay
	round    int
	updated  time.Time
	err      string
	running  bool
	capped   bool
	restart  chan struct{}
	lastHist time.Time
}

func newBoard(a *App) *Board {
	return &Board{app: a, data: map[string][]BoardRound{}, restart: make(chan struct{}, 1)}
}

// Restart übernimmt geänderte Länder oder Intervalle.
func (b *Board) Restart() {
	select {
	case b.restart <- struct{}{}:
	default:
	}
}

const boardScript = `I=%d; C=%d; W='%s'; P=40
IF=""; [ -n "$W" ] && IF="-I $W"
O=""; D=$((C+3))
if ping -c 1 -i 0.2 -W 1 127.0.0.1 >/dev/null 2>&1; then O="-i 0.2"; D=3; fi
echo "PID $$"
n=0
one() {
  ping -c $C $O -W 1 -w $D $IF "$1" 2>/dev/null | awk -v ip="$1" -v n=$C '
    /time=/ && !/DUP!/ { t=$0; sub(/.*time=/,"",t); sub(/[ ]*ms.*/,"",t); t+=0; c++; s+=t
      if(c==1||t<mn)mn=t; if(c==1||t>mx)mx=t; if(c>1){d=t-p; if(d<0)d=-d; js+=d; jc++} p=t }
    END { if(c>n)c=n
      if(c>0) printf "B %%s %%.2f %%.2f %%.2f %%.2f %%d\n", ip, s/c, (jc?js/jc:0), mn, mx, c
      else printf "B %%s 0 0 0 0 0\n", ip }'
}
while :; do
  n=$((n+1)); i=0
  for ip in %s; do one "$ip" & i=$((i+1)); [ $((i %% P)) -eq 0 ] && wait; done
  wait
  echo "ROUND $n"
  sleep $I
done
`

// Run läuft die ganze Programmlaufzeit und startet die Messschleife bei Bedarf neu.
func (b *Board) Run() {
	for !b.app.quitting() {
		cfg := b.app.store.Get()
		ok, _, inf := b.app.router.State()
		if !cfg.BoardOn || !ok {
			b.setRunning(false, "")
			select {
			case <-b.restart:
			case <-time.After(3 * time.Second):
			}
			continue
		}
		list := b.app.relays.ByCountries(cfg.BoardCountries)
		sort.Slice(list, func(i, j int) bool { return list[i].Host < list[j].Host })
		capped := false
		if len(list) > boardMax {
			list, capped = list[:boardMax], true
		}
		var ips []string
		byIP := map[string]Relay{}
		for _, r := range list {
			if ip := net.ParseIP(r.IPv4); ip != nil && ip.To4() != nil {
				ips = append(ips, ip.To4().String())
				byIP[ip.To4().String()] = r
			}
		}
		if len(ips) == 0 {
			b.setRunning(false, b.app.tr("Keine Server für diese Länder", "No servers for these countries"))
			select {
			case <-b.restart:
			case <-time.After(10 * time.Second):
			}
			continue
		}
		wan := ""
		if reIface.MatchString(inf.WAN) {
			wan = inf.WAN
		}
		b.mu.Lock()
		b.relays, b.capped = byIP, capped
		// Daten von Servern behalten, die weiterhin dabei sind
		keep := map[string][]BoardRound{}
		for _, r := range byIP {
			if d, ok := b.data[r.Host]; ok {
				keep[r.Host] = d
			}
		}
		b.data = keep
		b.mu.Unlock()
		script := fmt.Sprintf(boardScript, cfg.BoardInterval, boardPings, wan, strings.Join(ips, " "))
		b.setRunning(true, "")
		err := b.session(script)
		if b.app.quitting() {
			return
		}
		if err != nil {
			b.setRunning(false, err.Error())
			time.Sleep(5 * time.Second)
		}
	}
}

func (b *Board) setRunning(r bool, errText string) {
	b.mu.Lock()
	changed := b.running != r || b.err != errText
	b.running, b.err = r, errText
	b.mu.Unlock()
	if changed {
		b.app.broadcast("board", b.State())
	}
}

func (b *Board) session(script string) error {
	s, err := b.app.router.Session()
	if err != nil {
		return err
	}
	defer s.Close()
	s.Stdin = strings.NewReader(script)
	out, err := s.StdoutPipe()
	if err != nil {
		return err
	}
	if err := s.Start("sh -s"); err != nil {
		return err
	}
	lines := make(chan string, 256)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	pid := ""
	defer func() {
		if _, err := strconv.Atoi(pid); err == nil {
			go b.app.router.Run("kill "+pid+" 2>/dev/null", 5*time.Second)
		}
	}()
	pending := map[string]BoardRound{}
	for {
		select {
		case <-b.restart:
			return nil
		case l, ok := <-lines:
			if !ok {
				return errors.New(b.app.tr("Messschleife beendet", "measuring loop ended"))
			}
			f := strings.Fields(l)
			switch {
			case len(f) == 2 && f[0] == "PID":
				pid = f[1]
			case len(f) == 7 && f[0] == "B":
				var r BoardRound
				r.Avg, _ = strconv.ParseFloat(f[2], 64)
				r.Jit, _ = strconv.ParseFloat(f[3], 64)
				r.Min, _ = strconv.ParseFloat(f[4], 64)
				r.Max, _ = strconv.ParseFloat(f[5], 64)
				r.Recv, _ = strconv.Atoi(f[6])
				r.T = time.Now().UnixMilli()
				pending[f[1]] = r
			case len(f) == 2 && f[0] == "ROUND":
				b.commit(pending)
				pending = map[string]BoardRound{}
			}
		}
	}
}

func (b *Board) commit(p map[string]BoardRound) {
	if b.app.speed != nil && b.app.speed.Running() {
		return // volle Leitung verfälscht die Latenz – Runde verwerfen
	}
	b.mu.Lock()
	for ip, r := range p {
		rl, ok := b.relays[ip]
		if !ok {
			continue
		}
		d := append(b.data[rl.Host], r)
		if len(d) > boardKeep {
			d = d[len(d)-boardKeep:]
		}
		b.data[rl.Host] = d
	}
	b.round++
	b.updated = time.Now()
	saveHist := time.Since(b.lastHist) > 15*time.Minute && b.round >= boardWindow
	if saveHist {
		b.lastHist = time.Now()
	}
	b.mu.Unlock()
	st := b.State()
	b.app.broadcast("board", st)
	if saveHist {
		var snap []HistEntry
		now := time.Now().Unix()
		for _, r := range st.Rows {
			if r.Rounds >= boardWindow {
				snap = append(snap, HistEntry{T: now, CC: r.CountryCode, Host: r.Host, Avg: r.Median, Loss: r.Loss})
			}
		}
		b.app.hist.Add(snap)
	}
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	m := len(c) / 2
	if len(c)%2 == 1 {
		return c[m]
	}
	return (c[m-1] + c[m]) / 2
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// State liefert die sortierte Bestenliste.
func (b *Board) State() BoardState {
	cfg := b.app.store.Get()
	active := b.app.activeHosts()
	b.mu.Lock()
	st := BoardState{
		On: cfg.BoardOn, Running: b.running, Countries: cfg.BoardCountries, Interval: cfg.BoardInterval,
		Round: b.round, Updated: b.updated, Error: b.err, Capped: b.capped,
	}
	for _, rl := range b.relays {
		d := b.data[rl.Host]
		row := BoardRow{Relay: rl, Now: -1, Active: active[rl.Host], Stability: -1, Rounds: len(d)}
		if len(d) > 0 {
			last := d[len(d)-1]
			if last.Recv > 0 {
				row.Now = round1(last.Avg)
			}
			w := d
			if len(w) > boardWindow {
				w = w[len(w)-boardWindow:]
			}
			var avgs []float64
			sent, recv, jsum := 0, 0, 0.0
			for _, r := range w {
				sent += boardPings
				recv += r.Recv
				if r.Recv > 0 {
					avgs = append(avgs, r.Avg)
					jsum += r.Jit
				}
			}
			if len(avgs) > 0 {
				row.Median = round1(median(avgs))
				row.Jitter = round1(jsum / float64(len(avgs)))
			}
			if sent > 0 {
				row.Loss = round1(float64(sent-recv) * 100 / float64(sent))
			}
			sp := d
			if len(sp) > 30 {
				sp = sp[len(sp)-30:]
			}
			for _, r := range sp {
				if r.Recv > 0 {
					row.Spark = append(row.Spark, round1(r.Avg))
				} else {
					row.Spark = append(row.Spark, -1)
				}
			}
		}
		st.Rows = append(st.Rows, row)
	}
	b.mu.Unlock()
	stab := b.app.hist.Stability(7 * 24 * time.Hour)
	for i := range st.Rows {
		if v, ok := stab[st.Rows[i].Host]; ok {
			st.Rows[i].Stability = v
		}
	}
	sortBoard(st.Rows)
	return st
}

// sortBoard: Server mit Messwerten vor solchen ohne, dann Verlust, dann Median.
func sortBoard(rows []BoardRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		ha, hb := a.Median > 0, b.Median > 0
		if ha != hb {
			return ha
		}
		if a.Loss != b.Loss {
			return a.Loss < b.Loss
		}
		if a.Median != b.Median {
			return a.Median < b.Median
		}
		return a.Host < b.Host
	})
}

// Best liefert den besten Server eines Landes laut Bestenliste (mind. halbes Fenster an Daten).
func (b *Board) Best(cc string) (BoardRow, bool) {
	for _, r := range b.State().Rows {
		if r.CountryCode == cc && r.Median > 0 && r.Rounds >= boardWindow/2 {
			return r, true
		}
	}
	return BoardRow{}, false
}

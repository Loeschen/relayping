package main

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var reReply = regexp.MustCompile(`seq=(\d+).*time=([0-9.]+)\s*ms`)

const maxMonitors = 8

// Sample ist ein einzelner Ping: ms < 0 bedeutet verloren.
type Sample struct {
	Host string  `json:"host"`
	T    int64   `json:"t"` // Unix-Millisekunden
	Ms   float64 `json:"ms"`
}

type Monitor struct {
	app    *App
	relay  Relay
	stop   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	status string // "läuft", "verbinde", Fehlertext
	pid    string

	// Minutenwerte für den CSV-Verlauf
	bucket minuteBucket
	// letzte Messwerte für Warnungen (ms < 0 = verloren)
	recent []Sample
}

type WindowStats struct {
	N, Recv int
	Loss    float64
	Avg     float64
}

// Window fasst die Messwerte der letzten d zusammen.
func (m *Monitor) Window(d time.Duration) WindowStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	cut := time.Now().Add(-d).UnixMilli()
	var st WindowStats
	sum := 0.0
	for _, s := range m.recent {
		if s.T < cut {
			continue
		}
		st.N++
		if s.Ms >= 0 {
			st.Recv++
			sum += s.Ms
		}
	}
	if st.N > 0 {
		st.Loss = float64(st.N-st.Recv) * 100 / float64(st.N)
	}
	if st.Recv > 0 {
		st.Avg = sum / float64(st.Recv)
	}
	return st
}

type minuteBucket struct {
	start       time.Time
	sent, recv  int
	sum, mn, mx float64
	jsum        float64
	jn          int
	last        float64
}

func (b *minuteBucket) add(ms float64) {
	b.sent++
	if ms < 0 {
		return
	}
	if b.recv == 0 || ms < b.mn {
		b.mn = ms
	}
	if b.recv == 0 || ms > b.mx {
		b.mx = ms
	}
	if b.recv > 0 {
		b.jsum += math.Abs(ms - b.last)
		b.jn++
	}
	b.last = ms
	b.recv++
	b.sum += ms
}

func newMonitor(app *App, rl Relay) *Monitor {
	return &Monitor{app: app, relay: rl, stop: make(chan struct{}), status: "verbinde"}
}

func (m *Monitor) Status() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Monitor) setStatus(s string) {
	m.mu.Lock()
	changed := m.status != s
	m.status = s
	m.mu.Unlock()
	if changed {
		m.app.pushState()
	}
}

func (m *Monitor) Stop() {
	m.once.Do(func() { close(m.stop) })
}

func (m *Monitor) stopped() bool {
	select {
	case <-m.stop:
		return true
	default:
		return false
	}
}

func (m *Monitor) emit(ms float64, at time.Time) {
	m.mu.Lock()
	if m.bucket.start.IsZero() {
		m.bucket.start = at.Truncate(time.Minute)
	}
	if at.Truncate(time.Minute).After(m.bucket.start) {
		m.flushLocked()
		m.bucket = minuteBucket{start: at.Truncate(time.Minute)}
	}
	m.bucket.add(ms)
	m.recent = append(m.recent, Sample{Host: m.relay.Host, T: at.UnixMilli(), Ms: ms})
	if len(m.recent) > 900 {
		m.recent = m.recent[len(m.recent)-600:]
	}
	m.mu.Unlock()
	m.app.broadcast("sample", Sample{Host: m.relay.Host, T: at.UnixMilli(), Ms: math.Round(ms*100) / 100})
}

func (m *Monitor) flushLocked() {
	b := m.bucket
	if b.sent == 0 {
		return
	}
	m.app.csv.Live(b.start, m.relay, b)
}

func (m *Monitor) Run() {
	defer func() {
		m.mu.Lock()
		m.flushLocked()
		m.mu.Unlock()
	}()
	for !m.stopped() {
		err := m.session()
		if m.stopped() {
			return
		}
		if err != nil {
			m.setStatus(err.Error())
		}
		select {
		case <-m.stop:
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (m *Monitor) session() error {
	s, err := m.app.router.Session()
	if err != nil {
		return errors.New(m.app.tr("wartet auf Router", "waiting for router"))
	}
	defer s.Close()
	out, err := s.StdoutPipe()
	if err != nil {
		return err
	}
	ifopt := m.app.router.PingIfaceOpt()
	cmd := fmt.Sprintf(`sh -c 'echo PID $$; exec ping %s %s 2>&1'`, ifopt, m.relay.IPv4)
	if err := s.Start(cmd); err != nil {
		return err
	}
	m.setStatus("laeuft")

	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	lastSeq := -1
	lastRecv := time.Now()
	timerLost := 0
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	defer m.killRemote()

	for {
		select {
		case <-m.stop:
			return nil
		case l, ok := <-lines:
			if !ok {
				return errors.New(m.app.tr("Ping beendet, starte neu", "ping ended, restarting"))
			}
			if strings.HasPrefix(l, "PID ") {
				m.mu.Lock()
				m.pid = strings.TrimSpace(strings.TrimPrefix(l, "PID "))
				m.mu.Unlock()
				continue
			}
			if strings.Contains(l, "DUP!") {
				continue
			}
			mt := reReply.FindStringSubmatch(l)
			if mt == nil {
				if strings.Contains(strings.ToLower(l), "unreachable") || strings.Contains(l, "bad address") {
					m.setStatus("nicht erreichbar")
				}
				continue
			}
			seq, _ := strconv.Atoi(mt[1])
			ms, _ := strconv.ParseFloat(mt[2], 64)
			now := time.Now()
			if lastSeq >= 0 && seq > lastSeq+1 {
				gap := seq - lastSeq - 1 - timerLost
				for i := 0; i < gap; i++ {
					m.emit(-1, now)
				}
			}
			if lastSeq >= 0 && seq <= lastSeq {
				continue // verspätete Antwort, bereits als verloren gezaehlt
			}
			timerLost = 0
			lastSeq = seq
			lastRecv = now
			m.setStatus("laeuft")
			m.emit(ms, now)
		case now := <-tick.C:
			// keine Antwort seit > 2 s: pro fehlender Sekunde ein Verlust
			if now.Sub(lastRecv) > time.Duration(2+timerLost)*time.Second {
				timerLost++
				m.emit(-1, now)
				if timerLost >= 3 {
					m.setStatus("keine Antwort")
				}
			}
		}
	}
}

func (m *Monitor) killRemote() {
	m.mu.Lock()
	pid := m.pid
	m.pid = ""
	m.mu.Unlock()
	if _, err := strconv.Atoi(pid); err == nil {
		go m.app.router.Run("kill "+pid+" 2>/dev/null", 5*time.Second)
	}
}

// Recent liefert die gespeicherten Messwerte als [Zeit, ms]-Paare (ms < 0 = verloren),
// damit eine neu geöffnete Oberfläche den Verlauf sofort zeigen kann.
func (m *Monitor) Recent() [][2]float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][2]float64, 0, len(m.recent))
	for _, s := range m.recent {
		out = append(out, [2]float64{float64(s.T), math.Round(s.Ms*100) / 100})
	}
	return out
}

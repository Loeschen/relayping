package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// PC-Modus: Wer keinen Router mit SSH hat (z. B. nur eine FRITZ!Box und die
// Mullvad-App), kann direkt vom PC aus messen. Die Pings laufen dann über die
// Windows-ICMP-Schnittstelle. Ist die Mullvad-App verbunden, geht der Ping durch
// deren Tunnel – dann RelayPing in der App unter „Split-Tunneling“ ausnehmen.
//
// Die Messungen erzeugen dieselben Textzeilen wie die Router-Skripte, damit
// Live-Ansicht, Bestenliste und Rangliste unverändert weiterarbeiten.

func (a *App) localMode() bool { return a.store.Get().LocalMode }

// pingStats pingt count-mal im Abstand gap und rechnet wie die Router-Skripte.
func pingStats(ip net.IP, count int, gap, timeout time.Duration, stop <-chan struct{}) (avg, jit, mn, mx float64, recv int) {
	var sum, js float64
	var prev float64
	jn := 0
	for i := 0; i < count; i++ {
		if i > 0 {
			select {
			case <-stop:
				return
			case <-time.After(gap):
			}
		}
		ms, ok := pingHost(ip, timeout)
		if !ok {
			continue
		}
		recv++
		sum += ms
		if recv == 1 || ms < mn {
			mn = ms
		}
		if recv == 1 || ms > mx {
			mx = ms
		}
		if recv > 1 {
			d := ms - prev
			if d < 0 {
				d = -d
			}
			js += d
			jn++
		}
		prev = ms
	}
	if recv > 0 {
		avg = sum / float64(recv)
	}
	if jn > 0 {
		jit = js / float64(jn)
	}
	return
}

type lineWriter struct {
	mu sync.Mutex
	w  *io.PipeWriter
}

func (l *lineWriter) printf(format string, args ...any) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := fmt.Fprintf(l.w, format+"\n", args...)
	return err == nil
}

// localPingStream: wie „ping <ip>“ – eine Antwortzeile pro Sekunde.
func localPingStream(ip string, stop <-chan struct{}) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		addr := net.ParseIP(ip)
		lw := &lineWriter{w: pw}
		for seq := 0; ; seq++ {
			start := time.Now()
			if ms, ok := pingHost(addr, time.Second); ok {
				if !lw.printf("64 bytes from %s: seq=%d ttl=64 time=%.2f ms", ip, seq, ms) {
					return
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Second - time.Since(start)):
			}
		}
	}()
	return pr
}

// runParallel führt f für alle ips aus, höchstens n gleichzeitig.
func runParallel(ips []string, n int, f func(string)) {
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer func() { <-sem; wg.Done() }()
			f(ip)
		}(ip)
	}
	wg.Wait()
}

// localBoardStream: wie das Bestenlisten-Skript (Zeilen „B …“ und „ROUND n“).
func localBoardStream(ips []string, interval, pings int, stop <-chan struct{}) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		lw := &lineWriter{w: pw}
		for n := 1; ; n++ {
			runParallel(ips, 24, func(ip string) {
				avg, jit, mn, mx, c := pingStats(net.ParseIP(ip), pings, 200*time.Millisecond, time.Second, stop)
				lw.printf("B %s %.2f %.2f %.2f %.2f %d", ip, avg, jit, mn, mx, c)
			})
			if !lw.printf("ROUND %d", n) {
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Duration(interval) * time.Second):
			}
		}
	}()
	return pr
}

// localScanStream: wie das Ranglisten-Skript (Zeilen „R …“, am Ende „DONE“).
func localScanStream(ips []string, pings int, stop <-chan struct{}) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		lw := &lineWriter{w: pw}
		runParallel(ips, 24, func(ip string) {
			select {
			case <-stop:
				return
			default:
			}
			avg, jit, mn, mx, c := pingStats(net.ParseIP(ip), pings, 200*time.Millisecond, 2*time.Second, stop)
			loss := int(float64(pings-c)*100/float64(pings) + 0.5)
			if c == 0 {
				lw.printf("R %s 100 0 0 0 0 0", ip)
				return
			}
			lw.printf("R %s %d %.2f %.2f %.2f %.2f %d", ip, loss, avg, jit, mn, mx, c)
		})
		lw.printf("DONE")
	}()
	return pr
}

// SetLocalMode schaltet zwischen Router- und PC-Messung um.
func (a *App) SetLocalMode(on bool) error {
	if err := a.store.Update(func(c *Config) { c.LocalMode = on }); err != nil {
		return err
	}
	a.stopAllMonitors()
	if on {
		a.router.Disconnect()
		a.log.Printf("PC-Modus: Messung vom PC aus (ohne Router)")
		a.startLocal()
	} else {
		a.log.Printf("PC-Modus aus: Messung wieder über den Router")
		if a.router.HasKey() {
			go func() {
				if err := a.router.ConnectKey(); err != nil {
					a.router.EnsureReconnect()
				}
			}()
		}
	}
	a.board.Restart()
	a.pushState()
	return nil
}

// startLocal startet im PC-Modus die gemerkten Live-Server.
func (a *App) startLocal() {
	for _, h := range a.store.Get().Watch {
		_ = a.startMonitor(h, false)
	}
	a.board.Restart()
	localTickOnce.Do(func() {
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-a.quit:
					return
				case <-t.C:
					if a.localMode() {
						a.updateTray()
						a.broadcast("state", a.State())
					}
				}
			}
		}()
	})
}

var localTickOnce sync.Once

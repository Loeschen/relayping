package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CSV im deutschen Excel-Format: Semikolon, Dezimalkomma, UTF-8 mit BOM.
type CSVLog struct {
	app *App
	mu  sync.Mutex
}

func (c *CSVLog) dir() string { return c.app.store.File("verlauf") }

func de(f float64) string { return strings.Replace(fmt.Sprintf("%.1f", f), ".", ",", 1) }

func (c *CSVLog) write(name, header string, rows []string) {
	if !c.app.store.Get().LogCSV || len(rows) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.MkdirAll(c.dir(), 0o755)
	p := filepath.Join(c.dir(), name)
	_, statErr := os.Stat(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if os.IsNotExist(statErr) {
		f.WriteString("\xef\xbb\xbf" + header + "\r\n")
	}
	for _, r := range rows {
		f.WriteString(r + "\r\n")
	}
}

func (c *CSVLog) Live(start time.Time, r Relay, b minuteBucket) {
	loss := 0
	if b.sent > 0 {
		loss = (b.sent - b.recv) * 100 / b.sent
	}
	avg, jit := 0.0, 0.0
	if b.recv > 0 {
		avg = b.sum / float64(b.recv)
	}
	if b.jn > 0 {
		jit = b.jsum / float64(b.jn)
	}
	row := fmt.Sprintf("%s;%s;%s;%d;%d;%d;%s;%s;%s;%s",
		start.Format("02.01.2006 15:04"), r.Host, r.City, b.sent, b.recv, loss, de(avg), de(b.mn), de(b.mx), de(jit))
	c.write("live-minutenwerte.csv", "Zeitpunkt;Server;Stadt;Gesendet;Empfangen;Verlust %;Mittel ms;Min ms;Max ms;Jitter ms", []string{row})
}

func (c *CSVLog) Scan(st ScanState) {
	var rows []string
	ts := st.Finished.Format("02.01.2006 15:04")
	for i, r := range st.Results {
		act := ""
		if r.Active {
			act = "aktiv"
		}
		rows = append(rows, fmt.Sprintf("%s;%d;%s;%s;%s;%d;%d;%s;%s;%s;%s;%s",
			ts, i+1, r.Host, strings.ToUpper(r.CountryCode), r.City, st.Pings, r.Loss, de(r.Avg), de(r.Jitter), de(r.Min), de(r.Max), act))
	}
	c.write("ranglisten.csv", "Zeitpunkt;Platz;Server;Land;Stadt;Pings;Verlust %;Mittel ms;Jitter ms;Min ms;Max ms;Tunnel", rows)
}

func (c *CSVLog) Switch(t time.Time, tunnel, from, to, stage, msg string, dur time.Duration) {
	// Wechsel werden unabhängig von der CSV-Einstellung protokolliert.
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.MkdirAll(c.dir(), 0o755)
	p := filepath.Join(c.dir(), "wechsel.csv")
	_, statErr := os.Stat(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if os.IsNotExist(statErr) {
		f.WriteString("\xef\xbb\xbfZeitpunkt;Tunnel;Von;Nach;Ergebnis;Dauer s;Meldung\r\n")
	}
	f.WriteString(fmt.Sprintf("%s;%s;%s;%s;%s;%s;%s\r\n", t.Format("02.01.2006 15:04:05"), tunnel, from, to, stage,
		de(dur.Seconds()), strings.ReplaceAll(msg, ";", ",")))
}

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ping nach Wochentag und Uhrzeit: wertet verlauf/live-minutenwerte.csv aus
// (Minutenwerte der live beobachteten Server, z. B. der Tunnel-Server).
// So sieht man, ob ein Server zu bestimmten Zeiten (z. B. abends) langsamer wird.

type HeatCell struct {
	Ms   float64 `json:"ms"`   // Ø Ping
	Loss float64 `json:"loss"` // Verlust in %
	Mins int     `json:"mins"` // gemessene Minuten
}

type HeatServer struct {
	Host    string           `json:"host"`
	City    string           `json:"city"`
	Mins    int              `json:"mins"`
	Grid    [7][24]*HeatCell `json:"grid"` // [Mo..So][0..23]
	Min     float64          `json:"min"`
	Max     float64          `json:"max"`
	Base    float64          `json:"base"`    // ruhige Zeit: Median der Stundenwerte
	Evening float64          `json:"evening"` // Ø 19–23 Uhr
	Night   float64          `json:"night"`   // Ø 2–7 Uhr
	Worst   string           `json:"worst"`   // langsamste Stunde, z. B. "Fr 21 Uhr"
}

type HeatResult struct {
	Days    int          `json:"days"`
	From    int64        `json:"from"`
	To      int64        `json:"to"`
	Servers []HeatServer `json:"servers"`
	CSVOff  bool         `json:"csv_off"`
}

type heatAcc struct {
	sum        float64
	sent, recv int
	mins       int
	city       string
	grid       [7][24]struct {
		sum              float64
		sent, recv, mins int
	}
}

var heatCache struct {
	sync.Mutex
	at   time.Time
	days int
	res  HeatResult
}

func (a *App) Heat(days int) HeatResult {
	if days < 1 || days > 90 {
		days = 28
	}
	heatCache.Lock()
	defer heatCache.Unlock()
	if heatCache.days == days && time.Since(heatCache.at) < 5*time.Minute {
		return heatCache.res
	}
	res := buildHeat(filepath.Join(a.csv.dir(), "live-minutenwerte.csv"), days, time.Now())
	res.CSVOff = !a.store.Get().LogCSV
	heatCache.at, heatCache.days, heatCache.res = time.Now(), days, res
	return res
}

func deFloat(s string) float64 {
	v, _ := strconv.ParseFloat(strings.Replace(strings.TrimSpace(s), ",", ".", 1), 64)
	return v
}

var dayNames = [7]string{"Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"}

func buildHeat(path string, days int, now time.Time) HeatResult {
	res := HeatResult{Days: days, Servers: []HeatServer{}}
	f, err := os.Open(path)
	if err != nil {
		return res
	}
	defer f.Close()
	cut := now.AddDate(0, 0, -days)
	acc := map[string]*heatAcc{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ";")
		if len(p) < 7 {
			continue
		}
		t, err := time.ParseInLocation("02.01.2006 15:04", strings.TrimPrefix(p[0], "\xef\xbb\xbf"), time.Local)
		if err != nil || t.Before(cut) {
			continue
		}
		sent, _ := strconv.Atoi(p[3])
		recv, _ := strconv.Atoi(p[4])
		if sent <= 0 {
			continue
		}
		avg := deFloat(p[6])
		x := acc[p[1]]
		if x == nil {
			x = &heatAcc{city: p[2]}
			acc[p[1]] = x
		}
		wd := (int(t.Weekday()) + 6) % 7 // Montag = 0
		g := &x.grid[wd][t.Hour()]
		g.sum += avg * float64(recv)
		g.sent += sent
		g.recv += recv
		g.mins++
		x.mins++
		if res.From == 0 || t.Unix() < res.From {
			res.From = t.Unix()
		}
		if t.Unix() > res.To {
			res.To = t.Unix()
		}
	}
	for host, x := range acc {
		if x.mins < 60 {
			continue // weniger als eine Stunde gemessen
		}
		hs := HeatServer{Host: host, City: x.city, Mins: x.mins, Min: -1}
		var hourVals []float64
		var evS, evN, niS, niN float64
		worstV := -1.0
		for d := 0; d < 7; d++ {
			for h := 0; h < 24; h++ {
				g := x.grid[d][h]
				if g.mins == 0 || g.recv == 0 {
					if g.mins > 0 {
						hs.Grid[d][h] = &HeatCell{Loss: 100, Mins: g.mins}
					}
					continue
				}
				c := &HeatCell{Ms: round1(g.sum / float64(g.recv)), Loss: round1(float64(g.sent-g.recv) * 100 / float64(g.sent)), Mins: g.mins}
				hs.Grid[d][h] = c
				hourVals = append(hourVals, c.Ms)
				if hs.Min < 0 || c.Ms < hs.Min {
					hs.Min = c.Ms
				}
				if c.Ms > hs.Max {
					hs.Max = c.Ms
				}
				if h >= 19 && h <= 23 {
					evS += c.Ms * float64(c.Mins)
					evN += float64(c.Mins)
				}
				if h >= 2 && h <= 7 {
					niS += c.Ms * float64(c.Mins)
					niN += float64(c.Mins)
				}
				if c.Mins >= 10 && c.Ms > worstV {
					worstV = c.Ms
					hs.Worst = dayNames[d] + " " + strconv.Itoa(h)
				}
			}
		}
		if hs.Min < 0 {
			hs.Min = 0
		}
		hs.Base = round1(median(hourVals))
		if evN > 0 {
			hs.Evening = round1(evS / evN)
		}
		if niN > 0 {
			hs.Night = round1(niS / niN)
		}
		res.Servers = append(res.Servers, hs)
	}
	sort.Slice(res.Servers, func(i, j int) bool { return res.Servers[i].Mins > res.Servers[j].Mins })
	return res
}

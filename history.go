package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Verlauf für den Stabilitätswert: Momentaufnahmen aus Ranglisten und der
// Bestenliste (alle 15 Minuten). Gespeichert werden 7 Tage.

type HistEntry struct {
	T    int64   `json:"t"`
	CC   string  `json:"c"`
	Host string  `json:"h"`
	Avg  float64 `json:"a"`
	Loss float64 `json:"l"`
}

type History struct {
	mu      sync.Mutex
	file    string
	entries []HistEntry
	stab    map[string]float64
}

const histKeep = 7 * 24 * time.Hour

func newHistory(file string) *History {
	h := &History{file: file}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &h.entries)
	}
	h.mu.Lock()
	h.prune()
	h.stab = computeStability(h.entries, histKeep, time.Now())
	h.mu.Unlock()
	return h
}

func (h *History) prune() {
	cut := time.Now().Add(-histKeep).Unix()
	i := 0
	for i < len(h.entries) && h.entries[i].T < cut {
		i++
	}
	h.entries = h.entries[i:]
}

// Add hängt eine Momentaufnahme an (alle Einträge mit derselben Zeit T).
func (h *History) Add(snap []HistEntry) {
	if len(snap) == 0 {
		return
	}
	h.mu.Lock()
	h.entries = append(h.entries, snap...)
	h.prune()
	h.stab = computeStability(h.entries, histKeep, time.Now())
	b, err := json.Marshal(h.entries)
	h.mu.Unlock()
	if err == nil {
		tmp := h.file + ".tmp"
		if os.WriteFile(tmp, b, 0o644) == nil {
			_ = os.Rename(tmp, h.file)
		}
	}
}

// Stability: Anteil der Momentaufnahmen, in denen ein Server ohne Verlust
// höchstens 3 ms hinter dem besten Server seines Landes lag (0..100).
// Server mit weniger als 3 Aufnahmen fehlen in der Liste.
func (h *History) Stability(_ time.Duration) map[string]float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stab
}

func computeStability(entries []HistEntry, keep time.Duration, now time.Time) map[string]float64 {
	cut := now.Add(-keep).Unix()
	type key struct {
		t  int64
		cc string
	}
	best := map[key]float64{}
	for _, e := range entries {
		if e.T < cut || e.Avg <= 0 || e.Loss > 0 {
			continue
		}
		k := key{e.T, e.CC}
		if b, ok := best[k]; !ok || e.Avg < b {
			best[k] = e.Avg
		}
	}
	good := map[string]int{}
	total := map[string]int{}
	for _, e := range entries {
		if e.T < cut {
			continue
		}
		total[e.Host]++
		b, ok := best[key{e.T, e.CC}]
		if ok && e.Avg > 0 && e.Loss == 0 && e.Avg <= b+3 {
			good[e.Host]++
		}
	}
	out := map[string]float64{}
	for h, n := range total {
		if n >= 3 {
			out[h] = float64(good[h]) * 100 / float64(n)
		}
	}
	return out
}

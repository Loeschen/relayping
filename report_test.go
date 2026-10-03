package main

import (
	"testing"
	"time"
)

func TestSummarizeGrade(t *testing.T) {
	mins := []MinStat{
		{T: 60, Sent: 60, Recv: 60, Sum: 600, Min: 9, Max: 12, JSum: 30, JN: 59},
		{T: 120, Sent: 60, Recv: 57, Sum: 627, Min: 10, Max: 20, JSum: 60, JN: 56},
	}
	q := summarize(mins)
	if q.Minutes != 2 || q.BadMins != 1 || q.Loss != 2.5 || q.Min != 9 || q.Max != 20 || q.Avg != 10.5 {
		t.Errorf("summarize: %+v", q)
	}
	if g := grade(QStats{Minutes: 10, Avg: 10, Jitter: 1, Loss: 0}, 10); g != 4 {
		t.Errorf("sehr gut erwartet, %d", g)
	}
	if g := grade(QStats{Minutes: 10, Avg: 10, Jitter: 1, Loss: 3}, 10); g != 2 {
		t.Errorf("mäßig erwartet, %d", g)
	}
	if g := grade(QStats{Minutes: 10, Avg: 40, Jitter: 1}, 10); g != 2 {
		t.Errorf("langsam = mäßig erwartet, %d", g)
	}
	if g := grade(QStats{}, 10); g != 0 {
		t.Errorf("ohne Daten 0 erwartet, %d", g)
	}
}

func TestDaySegments(t *testing.T) {
	d := &Day{d: dayFile{Mins: map[string][]MinStat{}}}
	t0 := time.Unix(1_700_000_000, 0)
	d.Tunnels([]Tunnel{{Iface: "wg1", Host: "a"}}, t0)
	d.Tunnels([]Tunnel{{Iface: "wg1", Host: "a"}}, t0.Add(10*time.Second))
	d.Tunnels([]Tunnel{{Iface: "wg1", Host: "b"}}, t0.Add(20*time.Second))
	d.Tunnels([]Tunnel{{Iface: "wg1", Host: "b"}}, t0.Add(20*time.Minute)) // Lücke > 5 min
	if len(d.d.Segs) != 3 || d.d.Segs[0].To != t0.Unix()+10 || d.d.Segs[1].Host != "b" {
		t.Errorf("Abschnitte falsch: %+v", d.d.Segs)
	}
}

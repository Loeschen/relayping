package main

import (
	"testing"
	"time"
)

func feed(p *probeStream, t0 time.Time, from, to int, skip map[int]bool, delay func(int) time.Duration) {
	for q := from; q <= to; q++ {
		if skip[q] {
			continue
		}
		d := 10 * time.Millisecond
		if delay != nil {
			d += delay(q)
		}
		p.reply(q, t0.Add(time.Duration(q)*time.Second+d), 10)
	}
}

func TestBlipDetect(t *testing.T) {
	a := newTestApp(t)
	b := newBlips(a)
	t0 := time.Unix(1_800_000_000, 0)
	w1, w2, tu := &probeStream{}, &probeStream{}, &probeStream{}
	b.streams = map[string]*probeStream{"w1": w1, "w2": w2, "t:wg0": tu}
	b.names = map[string]string{"wg0": "Traffic"}
	// Start: nur Marken setzen
	feed(w1, t0, 0, 2, nil, nil)
	feed(w2, t0, 0, 2, nil, nil)
	feed(tu, t0, 0, 2, nil, nil)
	if r := b.evaluate(); len(r) != 0 {
		t.Fatalf("zu früh: %+v", r)
	}
	lostWAN := map[int]bool{10: true, 11: true, 12: true, 13: true}
	tunLoss := map[int]bool{10: true, 11: true, 12: true, 13: true, 20: true, 21: true, 22: true}
	single := map[int]bool{30: true}
	// LAN-Hänger: Zeilen von seq 40–45 kommen gebündelt 6 s zu spät an – darf nicht zählen
	late := func(q int) time.Duration {
		if q >= 40 && q <= 45 {
			return time.Duration(46-q) * time.Second
		}
		return 0
	}
	for _, x := range []map[int]bool{lostWAN, single} {
		for k := range x {
			_ = k
		}
	}
	w1skip := map[int]bool{}
	for k := range lostWAN {
		w1skip[k] = true
	}
	w1skip[30] = true
	feed(w1, t0, 3, 60, w1skip, late)
	feed(w2, t0, 3, 60, lostWAN, late)
	feed(tu, t0, 3, 60, tunLoss, late)
	_ = single
	r := b.evaluate()
	if len(r) != 2 {
		t.Fatalf("erwartet 2 Ereignisse, bekommen %+v", r)
	}
	var inet, tun *blipRun
	for i := range r {
		switch r[i].kind {
		case "kurz-internet":
			inet = &r[i]
		case "kurz-tunnel":
			tun = &r[i]
		}
	}
	if inet == nil || tun == nil || tun.target != "wg0" {
		t.Fatalf("Einordnung falsch: %+v", r)
	}
	if d := inet.end - inet.start; d < 3.5 || d > 4.5 {
		t.Fatalf("Internet-Dauer %.2f", d)
	}
	if d := tun.end - tun.start; d < 2.5 || d > 3.5 {
		t.Fatalf("Tunnel-Dauer %.2f", d)
	}
	if r := b.evaluate(); len(r) != 0 {
		t.Fatalf("doppelt gemeldet: %+v", r)
	}
	// langer Ausfall (40 s) wird nicht als Kurzaussetzer gezählt
	long := map[int]bool{}
	for q := 70; q < 110; q++ {
		long[q] = true
	}
	feed(w1, t0, 61, 130, long, nil)
	feed(w2, t0, 61, 130, long, nil)
	feed(tu, t0, 61, 130, long, nil)
	if r := b.evaluate(); len(r) != 0 {
		t.Fatalf("langer Ausfall gezählt: %+v", r)
	}
}

func TestBlipLAN(t *testing.T) {
	a := newTestApp(t)
	b := newBlips(a)
	t0 := time.Unix(1_800_000_000, 0)
	b.lanOK = true
	for i := 0; i < 5; i++ {
		b.lan.local(t0.Add(time.Duration(i)*time.Second), true)
	}
	b.evaluate()
	for i := 5; i < 30; i++ {
		b.lan.local(t0.Add(time.Duration(i)*time.Second), i < 10 || i > 12)
	}
	r := b.evaluate()
	if len(r) != 1 || r[0].kind != "kurz-lan" || r[0].end-r[0].start < 2.5 {
		t.Fatalf("%+v", r)
	}
}

func TestSeqWrap(t *testing.T) {
	var p probeStream
	t0 := time.Unix(1_800_000_000, 0)
	p.reply(65534, t0, 5)
	p.reply(65535, t0.Add(time.Second), 5)
	p.reply(1, t0.Add(3*time.Second), 5) // 0 fehlt
	if len(p.lost) != 1 || p.lastSeq != 65537 {
		t.Fatalf("%+v", p)
	}
}

func TestBlipMerge(t *testing.T) {
	a := newTestApp(t)
	o := newOutages(a, t.TempDir()+"/a.json")
	a.outages = o
	base := int64(1_800_000_000)
	if o.AddBlip("kurz-tunnel", "Traffic", base, base+5) {
		t.Fatal("erster Eintrag zusammengefasst")
	}
	for _, s := range []int64{6, 12, 20, 70} {
		if !o.AddBlip("kurz-tunnel", "Traffic", base+s, base+s+2) {
			t.Fatalf("%d nicht zusammengefasst", s)
		}
	}
	if o.AddBlip("kurz-tunnel", "Traffic", base+200, base+202) {
		t.Fatal("weit entfernter Aussetzer zusammengefasst")
	}
	if o.AddBlip("kurz-lan", "PC ↔ Router", base+201, base+203) {
		t.Fatal("andere Art zusammengefasst")
	}
	l := o.List()
	var first Outage
	for _, x := range l {
		if x.Start == base {
			first = x
		}
	}
	if len(l) != 3 || first.Count != 5 || first.Lost != 13 || first.End != base+72 {
		t.Fatalf("%+v", l)
	}
	if txt := a.outageText(first); txt == "" {
		t.Fatal("kein Text")
	}
}

func TestMergeOld(t *testing.T) {
	var l []Outage
	b := int64(1_800_000_000)
	for i, s := range []int64{0, 6, 12, 20, 25, 31, 35, 46, 53, 60, 68} {
		l = append(l, Outage{ID: int64(i + 1), Kind: "kurz-tunnel", Target: "wgclient2", Start: b + s, End: b + s + 2})
	}
	l = append(l, Outage{ID: 20, Kind: "kurz-internet", Target: "Internet", Start: b + 2300, End: b + 2303},
		Outage{ID: 21, Kind: "internet", Start: b + 5000, End: b + 5100})
	m := mergeBlips(l)
	if len(m) != 3 || m[0].Count != 11 || m[0].Lost != 22 || m[0].End != b+70 {
		t.Fatalf("%+v", m)
	}
}

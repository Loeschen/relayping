package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Relay struct {
	Host        string `json:"host"`
	CountryCode string `json:"cc"`
	Country     string `json:"country"`
	CityCode    string `json:"city_code"`
	City        string `json:"city"`
	IPv4        string `json:"ip"`
	PubKey      string `json:"pubkey,omitempty"`
	Owned       *bool  `json:"owned,omitempty"`
	Provider    string `json:"provider,omitempty"`
	SpeedGbps   int    `json:"speed,omitempty"`
}

type relayCache struct {
	Fetched time.Time `json:"abgerufen"`
	Relays  []Relay   `json:"server"`
}

type Relays struct {
	mu      sync.RWMutex
	list    []Relay
	byHost  map[string]*Relay
	byIP    map[string]*Relay
	byKey   map[string]*Relay
	fetched time.Time
	source  string
	file    string
}

var (
	apiV1  = envOr("MLAT_API_V1", "https://api.mullvad.net/public/relays/wireguard/v1/")
	apiWWW = envOr("MLAT_API_WWW", "https://api.mullvad.net/www/relays/wireguard/")
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func newRelays(cacheFile string) *Relays { return &Relays{file: cacheFile} }

// Load holt die Liste höchstens einmal pro Tag frisch, sonst aus dem Cache.
func (r *Relays) Load(force bool) error {
	var cache relayCache
	if b, err := os.ReadFile(r.file); err == nil {
		_ = json.Unmarshal(b, &cache)
	}
	if !force && len(cache.Relays) > 0 && time.Since(cache.Fetched) < 24*time.Hour {
		r.set(cache.Relays, cache.Fetched, "Zwischenspeicher")
		return nil
	}
	list, err := fetchRelays()
	if err != nil {
		if len(cache.Relays) > 0 {
			r.set(cache.Relays, cache.Fetched, "Zwischenspeicher (Abruf fehlgeschlagen)")
			return nil
		}
		return err
	}
	now := time.Now()
	if b, err := json.Marshal(relayCache{Fetched: now, Relays: list}); err == nil {
		_ = os.WriteFile(r.file, b, 0o644)
	}
	r.set(list, now, "Mullvad-API")
	return nil
}

func (r *Relays) set(list []Relay, t time.Time, src string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = list
	r.fetched, r.source = t, src
	r.byHost = map[string]*Relay{}
	r.byIP = map[string]*Relay{}
	r.byKey = map[string]*Relay{}
	for i := range r.list {
		x := &r.list[i]
		r.byHost[x.Host] = x
		r.byIP[x.IPv4] = x
		if x.PubKey != "" {
			r.byKey[x.PubKey] = x
		}
	}
}

func (r *Relays) All() []Relay {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Relay(nil), r.list...)
}

func (r *Relays) Host(h string) (Relay, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	x, ok := r.byHost[h]
	if !ok {
		return Relay{}, false
	}
	return *x, true
}

func (r *Relays) Match(ip, pubkey string) (Relay, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if x, ok := r.byKey[pubkey]; ok && pubkey != "" {
		return *x, true
	}
	if x, ok := r.byIP[ip]; ok {
		return *x, true
	}
	return Relay{}, false
}

func (r *Relays) Info() (int, time.Time, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.list), r.fetched, r.source
}

func (r *Relays) ByCountries(ccs []string) []Relay {
	want := map[string]bool{}
	all := false
	for _, c := range ccs {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "all" {
			all = true
		}
		want[c] = true
	}
	var out []Relay
	for _, x := range r.All() {
		if all || want[x.CountryCode] {
			out = append(out, x)
		}
	}
	return out
}

type v1Resp struct {
	Countries []struct {
		Name   string `json:"name"`
		Code   string `json:"code"`
		Cities []struct {
			Name   string `json:"name"`
			Code   string `json:"code"`
			Relays []struct {
				Hostname string `json:"hostname"`
				IPv4     string `json:"ipv4_addr_in"`
				PubKey   string `json:"public_key"`
			} `json:"relays"`
		} `json:"cities"`
	} `json:"countries"`
}

type wwwRelay struct {
	Hostname string `json:"hostname"`
	Active   *bool  `json:"active"`
	Owned    *bool  `json:"owned"`
	Provider string `json:"provider"`
	Speed    int    `json:"network_port_speed"`
}

func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 20<<20))
}

func fetchRelays() ([]Relay, error) {
	b, err := httpGet(apiV1)
	if err != nil {
		return nil, fmt.Errorf("Serverliste von Mullvad nicht abrufbar: %w", err)
	}
	var v v1Resp
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("Serverliste unlesbar: %w", err)
	}
	var out []Relay
	seen := map[string]bool{}
	for _, c := range v.Countries {
		for _, ci := range c.Cities {
			for _, r := range ci.Relays {
				ip := net.ParseIP(r.IPv4)
				if r.Hostname == "" || ip == nil || ip.To4() == nil || seen[r.Hostname] {
					continue
				}
				seen[r.Hostname] = true
				parts := strings.Split(r.Hostname, "-")
				cc, cityc := strings.ToLower(c.Code), strings.ToLower(ci.Code)
				if cc == "" && len(parts) > 0 {
					cc = parts[0]
				}
				if cityc == "" && len(parts) > 1 {
					cityc = parts[1]
				}
				out = append(out, Relay{
					Host: r.Hostname, CountryCode: cc, Country: c.Name,
					CityCode: cityc, City: ci.Name, IPv4: ip.To4().String(), PubKey: r.PubKey,
				})
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("Serverliste ist leer")
	}
	// Zusatzinfos (eigene/gemietete Server, Anbieter, Anbindung) - nur wenn verfügbar
	if b, err := httpGet(apiWWW); err == nil {
		var w []wwwRelay
		if json.Unmarshal(b, &w) == nil {
			m := map[string]wwwRelay{}
			for _, x := range w {
				m[x.Hostname] = x
			}
			kept := out[:0]
			for _, r := range out {
				if x, ok := m[r.Hostname()]; ok {
					if x.Active != nil && !*x.Active {
						continue
					}
					r.Owned, r.Provider, r.SpeedGbps = x.Owned, x.Provider, x.Speed
				}
				kept = append(kept, r)
			}
			out = kept
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, nil
}

func (r Relay) Hostname() string { return r.Host }

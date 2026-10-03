package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Config wird portabel neben der .exe gespeichert (relayping.json).
type Config struct {
	RouterHost string   `json:"router_host"`
	RouterPort int      `json:"router_port"`
	RouterUser string   `json:"router_user"`
	HostKey    string   `json:"router_host_key"` // im authorized_keys-Format, Trust on first use
	LogCSV     bool     `json:"csv_verlauf"`
	Countries  []string `json:"scan_laender"`
	ScanPings  int      `json:"scan_pings"`
	Watch      []string `json:"live_server"` // zuletzt beobachtete Server

	Lang           string              `json:"sprache"`                // "de" oder "en"
	Alerts         bool                `json:"warnungen"`              // Warnung bei schlechtem Tunnel
	AlertLossPct   int                 `json:"warn_verlust_prozent"`   // ab diesem Paketverlust warnen
	AlertExtraMs   float64             `json:"warn_mehr_ms"`           // so viel langsamer als der beste Server
	AutoScanMin    int                 `json:"auto_rangliste_minuten"` // 0 = aus
	BoardOn        bool                `json:"bestenliste_an"`
	BoardCountries []string            `json:"bestenliste_laender"`
	BoardInterval  int                 `json:"bestenliste_sekunden"`
	ChartScale     string              `json:"diagramm_achse"` // auto, lin, log
	Favorites      map[string][]string `json:"favoriten"`
}

type Store struct {
	mu   sync.Mutex
	dir  string
	path string
	c    Config
}

func defaultConfig() Config {
	return Config{
		RouterHost:     "192.168.8.1",
		RouterPort:     22,
		RouterUser:     "root",
		LogCSV:         true,
		Countries:      []string{"de", "se"},
		ScanPings:      20,
		Lang:           "de",
		Alerts:         true,
		AlertLossPct:   5,
		AlertExtraMs:   15,
		AutoScanMin:    60,
		BoardOn:        true,
		BoardCountries: []string{"de"},
		BoardInterval:  10,
		ChartScale:     "auto",
		Favorites:      map[string][]string{},
	}
}

// dataDir: Ordner der .exe, wenn beschreibbar – sonst %APPDATA%\RelayPing.
func dataDir() string {
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		if writable(d) {
			return d
		}
	}
	if d, err := os.UserConfigDir(); err == nil {
		d = filepath.Join(d, "RelayPing")
		_ = os.MkdirAll(d, 0o700)
		return d
	}
	return "."
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".schreibtest-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

func loadStore(dir string) *Store {
	s := &Store{dir: dir, path: filepath.Join(dir, "relayping.json"), c: defaultConfig()}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.c)
	}
	s.c.normalize()
	return s
}

func (c *Config) normalize() {
	d := defaultConfig()
	if c.RouterPort <= 0 || c.RouterPort > 65535 {
		c.RouterPort = 22
	}
	if c.RouterUser == "" {
		c.RouterUser = "root"
	}
	if c.ScanPings < 5 || c.ScanPings > 100 {
		c.ScanPings = 20
	}
	if len(c.Countries) == 0 {
		c.Countries = d.Countries
	}
	if c.Lang != "en" {
		c.Lang = "de"
	}
	if c.AlertLossPct < 1 || c.AlertLossPct > 50 {
		c.AlertLossPct = d.AlertLossPct
	}
	if c.AlertExtraMs < 3 || c.AlertExtraMs > 500 {
		c.AlertExtraMs = d.AlertExtraMs
	}
	if c.AutoScanMin != 0 && (c.AutoScanMin < 15 || c.AutoScanMin > 1440) {
		c.AutoScanMin = d.AutoScanMin
	}
	if len(c.BoardCountries) == 0 {
		c.BoardCountries = d.BoardCountries
	}
	if c.BoardInterval < 5 || c.BoardInterval > 120 {
		c.BoardInterval = d.BoardInterval
	}
	switch c.ChartScale {
	case "auto", "lin", "log":
	default:
		c.ChartScale = "auto"
	}
	if c.Favorites == nil {
		c.Favorites = map[string][]string{}
	}
}

func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.c
	c.Countries = append([]string(nil), s.c.Countries...)
	c.Watch = append([]string(nil), s.c.Watch...)
	c.BoardCountries = append([]string(nil), s.c.BoardCountries...)
	c.Favorites = map[string][]string{}
	for k, v := range s.c.Favorites {
		c.Favorites[k] = append([]string(nil), v...)
	}
	return c
}

func (s *Store) Update(fn func(c *Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.c)
	s.c.normalize()
	b, err := json.MarshalIndent(s.c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) File(name string) string { return filepath.Join(s.dir, name) }

// tr wählt den Text in der eingestellten Sprache.
func (a *App) tr(de, en string) string {
	if a != nil && a.store != nil && a.store.Get().Lang == "en" {
		return en
	}
	return de
}

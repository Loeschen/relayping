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
}

type Store struct {
	mu   sync.Mutex
	dir  string
	path string
	c    Config
}

func defaultConfig() Config {
	return Config{
		RouterHost: "192.168.8.1",
		RouterPort: 22,
		RouterUser: "root",
		LogCSV:     true,
		Countries:  []string{"de", "se"},
		ScanPings:  20,
	}
}

// dataDir: Ordner der .exe, wenn beschreibbar - sonst %APPDATA%\RelayPing.
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
	if s.c.RouterPort == 0 {
		s.c.RouterPort = 22
	}
	if s.c.RouterUser == "" {
		s.c.RouterUser = "root"
	}
	if s.c.ScanPings < 5 || s.c.ScanPings > 100 {
		s.c.ScanPings = 20
	}
	if len(s.c.Countries) == 0 {
		s.c.Countries = []string{"de", "se"}
	}
	return s
}

func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.c
	c.Countries = append([]string(nil), s.c.Countries...)
	c.Watch = append([]string(nil), s.c.Watch...)
	return c
}

func (s *Store) Update(fn func(c *Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.c)
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

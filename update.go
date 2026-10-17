package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Update-Hinweis: einmal am Tag fragt RelayPing bei GitHub nach der neuesten
// Version. Auf Wunsch lädt es sie, prüft die SHA-256-Prüfsumme und tauscht
// sich selbst aus (die alte Datei bleibt als RelayPing.old.exe liegen und wird
// beim nächsten Start entfernt).

var updateURL = envOr("RELAYPING_UPDATE_URL", "https://api.github.com/repos/Loeschen/relayping/releases?per_page=10")

type UpdateState struct {
	Current   string    `json:"current"`
	Available bool      `json:"available"`
	Tag       string    `json:"tag,omitempty"`
	Name      string    `json:"name,omitempty"`
	URL       string    `json:"url,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	ExeURL    string    `json:"-"`
	ShaURL    string    `json:"-"`
	CanApply  bool      `json:"can_apply"`
	Checked   time.Time `json:"checked"`
	Error     string    `json:"error,omitempty"`
	Applying  bool      `json:"applying"`
	ApplyMsg  string    `json:"apply_msg,omitempty"`
}

type Updater struct {
	app *App
	mu  sync.Mutex
	st  UpdateState
}

// parseVer: "v0.12.0-beta" -> [0 12 0], "beta"
func parseVer(s string) ([3]int, string) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	pre := ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s, pre = s[:i], s[i+1:]
	}
	var v [3]int
	for i, p := range strings.SplitN(s, ".", 3) {
		v[i], _ = strconv.Atoi(p)
	}
	return v, pre
}

// newerVer: ist a neuer als b?
func newerVer(a, b string) bool {
	va, pa := parseVer(a)
	vb, pb := parseVer(b)
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	if pa == pb {
		return false
	}
	if pa == "" {
		return true // Final schlägt Vorabversion
	}
	if pb == "" {
		return false
	}
	return pa > pb
}

func (u *Updater) State() UpdateState {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.st
	st.Current = version
	return st
}

func (u *Updater) Run() {
	cleanupOld()
	select {
	case <-u.app.quit:
		return
	case <-time.After(90 * time.Second):
	}
	for !u.app.quitting() {
		if u.app.store.Get().UpdateCheck {
			u.Check()
		}
		select {
		case <-u.app.quit:
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func (u *Updater) Check() UpdateState {
	a := u.app
	cl := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, updateURL, nil)
	req.Header.Set("User-Agent", "RelayPing/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")
	st := UpdateState{Checked: time.Now()}
	resp, err := cl.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
	if err != nil {
		st.Error = err.Error()
	} else {
		var rels []struct {
			Tag    string `json:"tag_name"`
			Name   string `json:"name"`
			Draft  bool   `json:"draft"`
			URL    string `json:"html_url"`
			Body   string `json:"body"`
			Assets []struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
			} `json:"assets"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&rels); err != nil {
			st.Error = err.Error()
		}
		best := version
		for _, r := range rels {
			if r.Draft || !newerVer(r.Tag, best) {
				continue
			}
			best = r.Tag
			st.Available, st.Tag, st.Name, st.URL = true, r.Tag, r.Name, r.URL
			st.Notes = r.Body
			if len(st.Notes) > 1500 {
				st.Notes = st.Notes[:1500] + " …"
			}
			st.ExeURL, st.ShaURL = "", ""
			for _, as := range r.Assets {
				switch strings.ToLower(as.Name) {
				case "relayping.exe":
					st.ExeURL = as.URL
				case "relayping.exe.sha256":
					st.ShaURL = as.URL
				}
			}
		}
		st.CanApply = st.Available && st.ExeURL != "" && st.ShaURL != "" && runtime.GOOS == "windows"
	}
	u.mu.Lock()
	prevTag := u.st.Tag
	u.st = st
	u.mu.Unlock()
	a.broadcast("update", u.State())
	if st.Available && st.Tag != prevTag {
		a.notify(a.tr("RelayPing: Update", "RelayPing: update"), fmt.Sprintf(a.tr("Version %s ist verfügbar.", "Version %s is available."), st.Tag))
		a.push("update", "RelayPing", fmt.Sprintf(a.tr("Version %s ist verfügbar.", "Version %s is available."), st.Tag))
	}
	return u.State()
}

func download(url string, max int64) ([]byte, error) {
	cl := &http.Client{Timeout: 5 * time.Minute}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "RelayPing/"+version)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// Apply lädt die neue Version, prüft die Prüfsumme und startet sie.
func (u *Updater) Apply() error {
	a := u.app
	u.mu.Lock()
	st := u.st
	if !st.CanApply || st.Applying {
		u.mu.Unlock()
		return errors.New(a.tr("Kein installierbares Update vorhanden", "No installable update available"))
	}
	u.st.Applying, u.st.ApplyMsg = true, a.tr("Lade herunter …", "Downloading …")
	u.mu.Unlock()
	a.broadcast("update", u.State())
	fail := func(err error) error {
		u.mu.Lock()
		u.st.Applying, u.st.ApplyMsg = false, ""
		u.mu.Unlock()
		a.broadcast("update", u.State())
		return err
	}
	shaTxt, err := download(st.ShaURL, 4096)
	if err != nil {
		return fail(fmt.Errorf(a.tr("Prüfsumme nicht ladbar: %v", "checksum not downloadable: %v"), err))
	}
	f := strings.Fields(string(shaTxt))
	if len(f) == 0 || len(f[0]) != 64 {
		return fail(errors.New(a.tr("Prüfsummen-Datei ungültig", "invalid checksum file")))
	}
	want := strings.ToLower(f[0])
	bin, err := download(st.ExeURL, 64<<20)
	if err != nil {
		return fail(fmt.Errorf(a.tr("Download fehlgeschlagen: %v", "download failed: %v"), err))
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != want {
		return fail(errors.New(a.tr("Prüfsumme stimmt nicht – Update verworfen", "checksum mismatch – update discarded")))
	}
	exe, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	dir := filepath.Dir(exe)
	newPath := filepath.Join(dir, "RelayPing.update.exe")
	if err := os.WriteFile(newPath, bin, 0o755); err != nil {
		return fail(fmt.Errorf(a.tr("Kann nicht in den Programmordner schreiben: %v", "cannot write to program folder: %v"), err))
	}
	old := filepath.Join(dir, "RelayPing.old.exe")
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(newPath)
		return fail(err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(old, exe)
		return fail(err)
	}
	a.log.Printf("Update auf %s installiert, starte neu", st.Tag)
	cmd := exec.Command(exe, "--after-update")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		_ = os.Rename(exe, newPath)
		_ = os.Rename(old, exe)
		return fail(err)
	}
	u.mu.Lock()
	u.st.ApplyMsg = a.tr("Neue Version startet …", "Starting new version …")
	u.mu.Unlock()
	a.broadcast("update", u.State())
	go func() { time.Sleep(800 * time.Millisecond); a.Quit() }()
	return nil
}

// cleanupOld entfernt die Vorgängerversion nach einem Update.
func cleanupOld() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	for i := 0; i < 10; i++ {
		err := os.Remove(filepath.Join(filepath.Dir(exe), "RelayPing.old.exe"))
		if err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Second)
	}
}

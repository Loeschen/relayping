package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	reIface = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)
	reHost  = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}$`)

	errHostKeyChanged = errors.New("Der SSH-Schlüssel des Routers hat sich geändert. Falls du den Router zurückgesetzt oder getauscht hast: in den Einstellungen „Router-Zugang zurücksetzen“.")
	errNoKey          = errors.New("noch nicht eingerichtet")
)

type Tunnel struct {
	Iface string `json:"iface"`
	IP    string `json:"ip"`
	Host  string `json:"host"`
	City  string `json:"city"`
	CC    string `json:"cc"`
}

type RouterInfo struct {
	WAN      string    `json:"wan"`
	FastPing bool      `json:"fastping"`
	Model    string    `json:"model"`
	Tunnels  []Tunnel  `json:"tunnels"`
	HasWG    bool      `json:"has_wg"`
	Checked  time.Time `json:"checked"`
}

type Router struct {
	app *App

	mu           sync.Mutex
	client       *ssh.Client
	connected    bool
	lastErr      string
	info         RouterInfo
	newHostKey   ssh.PublicKey
	reconnecting bool
}

func (r *Router) keyFile() string { return r.app.store.File("relayping.key") }

func (r *Router) HasKey() bool {
	_, err := os.Stat(r.keyFile())
	return err == nil
}

func (r *Router) State() (bool, string, RouterInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected, r.lastErr, r.info
}

func (r *Router) hostKeyCB(_ string, _ net.Addr, key ssh.PublicKey) error {
	stored := strings.TrimSpace(r.app.store.Get().HostKey)
	got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if stored == "" {
		r.newHostKey = key
		return nil
	}
	if stored != got {
		return errHostKeyChanged
	}
	return nil
}

func fingerprint(authorized string) string {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(k.Marshal())
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

func (r *Router) dial(auth []ssh.AuthMethod) (*ssh.Client, error) {
	c := r.app.store.Get()
	if !reHost.MatchString(c.RouterHost) {
		return nil, fmt.Errorf("Ungültige Router-Adresse")
	}
	cfg := &ssh.ClientConfig{
		User:            c.RouterUser,
		Auth:            auth,
		HostKeyCallback: r.hostKeyCB,
		Timeout:         6 * time.Second,
	}
	r.newHostKey = nil
	addr := net.JoinHostPort(c.RouterHost, strconv.Itoa(c.RouterPort))
	cl, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, friendlyErr(err)
	}
	if r.newHostKey != nil {
		hk := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(r.newHostKey)))
		_ = r.app.store.Update(func(c *Config) { c.HostKey = hk })
		r.newHostKey = nil
	}
	return cl, nil
}

func friendlyErr(err error) error {
	s := err.Error()
	switch {
	case errors.Is(err, errHostKeyChanged) || strings.Contains(s, "geändert"):
		return errHostKeyChanged
	case strings.Contains(s, "unable to authenticate"):
		return errors.New("Anmeldung abgelehnt – Passwort prüfen (es ist dasselbe wie im GL.iNet-Admin-Panel)")
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "no route") || strings.Contains(s, "connection refused"):
		return fmt.Errorf("Router nicht erreichbar (%v). Adresse prüfen und ob SSH aktiv ist", err)
	}
	return err
}

func (r *Router) signer() (ssh.Signer, error) {
	b, err := os.ReadFile(r.keyFile())
	if err != nil {
		return nil, errNoKey
	}
	return ssh.ParsePrivateKey(b)
}

// ConnectKey verbindet mit dem gespeicherten Schlüssel.
func (r *Router) ConnectKey() error {
	sg, err := r.signer()
	if err != nil {
		return err
	}
	cl, err := r.dial([]ssh.AuthMethod{ssh.PublicKeys(sg)})
	if err != nil {
		r.setErr(err)
		return err
	}
	r.attach(cl)
	return nil
}

// ConnectPassword meldet sich einmalig mit Passwort an und hinterlegt einen Schlüssel.
func (r *Router) ConnectPassword(pw string) error {
	if r.app.store.Get().HostKey == "" {
		// erster Kontakt: Host-Key wird beim Dial gespeichert (Trust on first use)
	}
	ki := ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
		a := make([]string, len(qs))
		for i := range a {
			a[i] = pw
		}
		return a, nil
	})
	cl, err := r.dial([]ssh.AuthMethod{ssh.Password(pw), ki})
	if err != nil {
		r.setErr(err)
		return err
	}
	if err := r.installKey(cl); err != nil {
		cl.Close()
		r.setErr(err)
		return fmt.Errorf("Anmeldung ok, aber Schlüssel konnte nicht hinterlegt werden: %w", err)
	}
	cl.Close()
	// Gegenprobe: klappt der Schlüssel?
	if err := r.ConnectKey(); err != nil {
		return fmt.Errorf("Schlüssel hinterlegt, aber Anmeldung damit fehlgeschlagen: %w", err)
	}
	return nil
}

func (r *Router) installKey(cl *ssh.Client) error {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " relayping"
	cmd := `umask 077; if [ -f /etc/openwrt_release ] && [ -d /etc/dropbear ]; then f=/etc/dropbear/authorized_keys; else mkdir -p "$HOME/.ssh"; f="$HOME/.ssh/authorized_keys"; fi; touch "$f"; grep -qxF '` + line + `' "$f" || echo '` + line + `' >> "$f"; echo OK`
	out, err := runOn(cl, cmd, 15*time.Second)
	if err != nil || !strings.Contains(out, "OK") {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(out))
	}
	block, err := ssh.MarshalPrivateKey(key, "relayping")
	if err != nil {
		return err
	}
	return os.WriteFile(r.keyFile(), pem.EncodeToMemory(block), 0o600)
}

func (r *Router) attach(cl *ssh.Client) {
	r.mu.Lock()
	if r.client != nil {
		r.client.Close()
	}
	r.client = cl
	r.connected = true
	r.lastErr = ""
	r.mu.Unlock()
	go r.keepalive(cl)
	r.Refresh()
	r.app.onConnected()
}

func (r *Router) setErr(err error) {
	r.mu.Lock()
	r.lastErr = err.Error()
	r.mu.Unlock()
	r.app.pushState()
}

func (r *Router) Disconnect() {
	r.mu.Lock()
	if r.client != nil {
		r.client.Close()
		r.client = nil
	}
	r.connected = false
	r.mu.Unlock()
}

func (r *Router) keepalive(cl *ssh.Client) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		r.mu.Lock()
		cur := r.client
		r.mu.Unlock()
		if cur != cl {
			return
		}
		errc := make(chan error, 1)
		go func() { _, _, err := cl.SendRequest("keepalive@openssh.com", true, nil); errc <- err }()
		var err error
		select {
		case err = <-errc:
		case <-time.After(8 * time.Second):
			err = errors.New("Zeitüberschreitung")
		}
		if err != nil {
			r.lost(cl, fmt.Errorf("Verbindung zum Router verloren (%v)", err))
			return
		}
	}
}

func (r *Router) lost(cl *ssh.Client, err error) {
	r.mu.Lock()
	if r.client != cl {
		r.mu.Unlock()
		return
	}
	cl.Close()
	r.client = nil
	r.connected = false
	r.lastErr = err.Error()
	start := !r.reconnecting
	r.reconnecting = true
	r.mu.Unlock()
	r.app.pushState()
	if start {
		go r.reconnectLoop()
	}
}

// EnsureReconnect startet die Wiederverbindung im Hintergrund (z. B. Router beim Start noch nicht erreichbar).
func (r *Router) EnsureReconnect() {
	r.mu.Lock()
	if r.reconnecting || r.connected {
		r.mu.Unlock()
		return
	}
	r.reconnecting = true
	r.mu.Unlock()
	go r.reconnectLoop()
}

func (r *Router) reconnectLoop() {
	defer func() { r.mu.Lock(); r.reconnecting = false; r.mu.Unlock() }()
	for i := 0; ; i++ {
		time.Sleep(time.Duration(min(5+i*2, 30)) * time.Second)
		if r.app.quitting() {
			return
		}
		if err := r.ConnectKey(); err == nil {
			return
		} else if errors.Is(err, errNoKey) || errors.Is(err, errHostKeyChanged) {
			return
		}
	}
}

// Session liefert eine neue SSH-Sitzung oder einen Fehler, wenn getrennt.
func (r *Router) Session() (*ssh.Session, error) {
	r.mu.Lock()
	cl := r.client
	r.mu.Unlock()
	if cl == nil {
		return nil, errors.New("nicht mit dem Router verbunden")
	}
	s, err := cl.NewSession()
	if err != nil {
		r.lost(cl, err)
		return nil, err
	}
	return s, nil
}

func (r *Router) Run(cmd string, timeout time.Duration) (string, error) {
	r.mu.Lock()
	cl := r.client
	r.mu.Unlock()
	if cl == nil {
		return "", errors.New("nicht mit dem Router verbunden")
	}
	return runOn(cl, cmd, timeout)
}

func runOn(cl *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	s, err := cl.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	var buf bytes.Buffer
	s.Stdout = &buf
	s.Stderr = io.Discard
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(timeout):
		s.Close()
		return buf.String(), errors.New("Zeitüberschreitung")
	}
}

const infoCmd = `W=""
if command -v ubus >/dev/null 2>&1 && command -v jsonfilter >/dev/null 2>&1; then W=$(ubus call network.interface.wan status 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null); fi
[ -z "$W" ] && W=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
echo "WAN=$W"
ping -c 1 -i 0.2 -W 1 127.0.0.1 >/dev/null 2>&1 && echo "FASTPING=1"
command -v wg >/dev/null 2>&1 && echo "HASWG=1"
wg show all endpoints 2>/dev/null | sed 's/^/EP /'
echo "MODEL=$(cat /tmp/sysinfo/model 2>/dev/null)"
`

// Refresh liest WAN-Schnittstelle und aktive Tunnel-Server neu ein.
func (r *Router) Refresh() {
	out, err := r.Run(infoCmd, 15*time.Second)
	if err != nil && out == "" {
		return
	}
	var inf RouterInfo
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(l, "WAN="):
			w := strings.TrimPrefix(l, "WAN=")
			if reIface.MatchString(w) && !strings.HasPrefix(w, "wg") && !strings.HasPrefix(w, "tun") {
				inf.WAN = w
			}
		case l == "FASTPING=1":
			inf.FastPing = true
		case l == "HASWG=1":
			inf.HasWG = true
		case strings.HasPrefix(l, "MODEL="):
			inf.Model = strings.TrimPrefix(l, "MODEL=")
		case strings.HasPrefix(l, "EP "):
			f := strings.Fields(strings.TrimPrefix(l, "EP "))
			if len(f) < 3 {
				continue
			}
			host, _, err := net.SplitHostPort(f[2])
			if err != nil {
				continue
			}
			t := Tunnel{Iface: f[0], IP: host}
			if rl, ok := r.app.relays.Match(host, f[1]); ok {
				t.Host, t.City, t.CC = rl.Host, rl.City, rl.CountryCode
			}
			inf.Tunnels = append(inf.Tunnels, t)
		}
	}
	inf.Checked = time.Now()
	r.mu.Lock()
	r.info = inf
	r.mu.Unlock()
	r.app.pushState()
}

func (r *Router) PingIfaceOpt() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.info.WAN != "" {
		return "-I " + r.info.WAN
	}
	return ""
}

// Forget löscht Schlüssel und gemerkten Host-Key (z. B. nach Router-Reset).
func (r *Router) Forget() {
	r.Disconnect()
	os.Remove(r.keyFile())
	_ = r.app.store.Update(func(c *Config) { c.HostKey = "" })
	r.mu.Lock()
	r.info = RouterInfo{}
	r.lastErr = ""
	r.mu.Unlock()
}

package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

//go:embed ui
var uiFS embed.FS

const version = "0.10.0-beta"

// runInfo erlaubt einer zweiten gestarteten Instanz, die laufende zu öffnen.
type runInfo struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
	PID   int    `json:"pid"`
}

func main() {
	hidden := false
	for _, a := range os.Args[1:] {
		if a == "--hidden" || a == "/hidden" {
			hidden = true
		}
	}
	dir := dataDir()
	runFile := dir + string(os.PathSeparator) + "relayping-run.json"

	if !acquireSingleInstance() {
		// läuft schon: Oberfläche der laufenden Instanz öffnen und beenden
		if b, err := os.ReadFile(runFile); err == nil {
			var ri runInfo
			if json.Unmarshal(b, &ri) == nil && ri.Addr != "" {
				openBrowser("http://" + ri.Addr + "/?k=" + ri.Token)
			}
		}
		return
	}

	app := newApp(dir)
	app.token = loadToken(dir)
	app.log.Printf("RelayPing %s startet (%s)", version, runtime.GOOS)

	ln, err := net.Listen("tcp", "127.0.0.1:"+envOr("RELAYPING_PORT", "47321"))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fatal(app, "Kein freier Port: "+err.Error())
			return
		}
	}
	app.addr = ln.Addr().String()
	url := "http://" + app.addr + "/?k=" + app.token
	if b, err := json.Marshal(runInfo{Addr: app.addr, Token: app.token, PID: os.Getpid()}); err == nil {
		_ = os.WriteFile(runFile, b, 0o600)
	}
	defer os.Remove(runFile)

	srv := &http.Server{Handler: app.routes(), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)

	open := func() { openBrowser(url) }
	if t, err := startTray(app, open); err == nil {
		app.tray = t
	} else {
		app.log.Printf("Taskleisten-Symbol nicht verfügbar: %v", err)
		showConsole(app, url)
	}

	go func() {
		if err := app.relays.Load(false); err != nil {
			app.mu.Lock()
			app.relayErr = err.Error()
			app.mu.Unlock()
			app.log.Printf("Serverliste: %v", err)
		}
		app.pushState()
		if app.router.HasKey() {
			if err := app.router.ConnectKey(); err != nil && !errors.Is(err, errHostKeyChanged) {
				app.router.EnsureReconnect()
			}
		}
	}()
	go app.board.Run()
	go app.alerts.Run()
	go app.scanner.AutoRun()

	if os.Getenv("RELAYPING_NO_BROWSER") != "" {
		fmt.Println("URL: " + url)
	} else if !hidden {
		go func() { time.Sleep(400 * time.Millisecond); open() }()
	}

	<-app.quit
	app.log.Printf("RelayPing wird beendet")
	app.tray.Close()
	app.stopAllMonitors()
	app.router.Disconnect()
	time.Sleep(300 * time.Millisecond)
}

// loadToken liefert einen dauerhaften Zugangsschlüssel für die Oberfläche, damit
// Lesezeichen und offene Tabs einen Neustart überstehen.
func loadToken(dir string) string {
	p := dir + string(os.PathSeparator) + "relayping-ui.key"
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return string(b)
	}
	b := make([]byte, 16)
	rand.Read(b)
	t := hex.EncodeToString(b)
	_ = os.WriteFile(p, []byte(t), 0o600)
	return t
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func fatal(app *App, msg string) {
	app.log.Printf("Fehler: %s", msg)
	showConsole(app, "")
	fmt.Println("Fehler:", msg)
	fmt.Println("Enter drücken zum Beenden.")
	var s string
	fmt.Scanln(&s)
}

//go:build !windows

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func startTray(app *App, open func()) (Tray, error) {
	return nil, errors.New("nur unter Windows")
}

func showConsole(app *App, url string) {
	fmt.Println("RelayPing " + version + " – inoffizielles Tool, nicht mit Mullvad VPN AB, GL.iNet, ASUS oder AVM verbunden")
	if url != "" {
		fmt.Println("Oberfläche: " + url)
	}
	fmt.Println("Daten:      " + app.store.dir)
}

func acquireSingleInstance() bool { return true }

func autostartEnabled() (bool, bool) { return false, false }

func setAutostart(bool) error { return errors.New("Autostart gibt es nur unter Windows") }

// Außerhalb von Windows (nur Entwicklung/Test): Passwort lediglich kodiert, nicht verschlüsselt.
func protectSecret(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	return "b64:" + base64.StdEncoding.EncodeToString([]byte(s)), nil
}

func unprotectSecret(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	raw, ok := strings.CutPrefix(s, "b64:")
	if !ok {
		return "", errors.New("unbekanntes Format")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	return string(b), err
}

// pingHost (nur Entwicklung/Test): ein Ping über das System-Programm.
func pingHost(ip net.IP, timeout time.Duration) (float64, bool) {
	sec := int(timeout.Seconds())
	if sec < 1 {
		sec = 1
	}
	out, err := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(sec), ip.String()).Output()
	if err != nil {
		return 0, false
	}
	if m := reReply.FindStringSubmatch(string(out)); m != nil {
		v, _ := strconv.ParseFloat(m[2], 64)
		return v, true
	}
	return 0, false
}

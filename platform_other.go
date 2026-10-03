//go:build !windows

package main

import (
	"errors"
	"fmt"
)

func startTray(app *App, open func()) (Tray, error) {
	return nil, errors.New("nur unter Windows")
}

func showConsole(app *App, url string) {
	fmt.Println("RelayPing " + version + " – inoffizielles Tool, nicht mit Mullvad VPN AB oder GL.iNet verbunden")
	if url != "" {
		fmt.Println("Oberfläche: " + url)
	}
	fmt.Println("Daten:      " + app.store.dir)
}

func acquireSingleInstance() bool { return true }

func autostartEnabled() (bool, bool) { return false, false }

func setAutostart(bool) error { return errors.New("Autostart gibt es nur unter Windows") }

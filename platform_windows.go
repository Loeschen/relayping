//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassExW       = user32.NewProc("RegisterClassExW")
	pCreateWindowExW        = user32.NewProc("CreateWindowExW")
	pDefWindowProcW         = user32.NewProc("DefWindowProcW")
	pGetMessageW            = user32.NewProc("GetMessageW")
	pTranslateMessage       = user32.NewProc("TranslateMessage")
	pDispatchMessageW       = user32.NewProc("DispatchMessageW")
	pPostQuitMessage        = user32.NewProc("PostQuitMessage")
	pPostMessageW           = user32.NewProc("PostMessageW")
	pCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	pAppendMenuW            = user32.NewProc("AppendMenuW")
	pTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	pDestroyMenu            = user32.NewProc("DestroyMenu")
	pSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	pGetCursorPos           = user32.NewProc("GetCursorPos")
	pLoadImageW             = user32.NewProc("LoadImageW")
	pLoadIconW              = user32.NewProc("LoadIconW")
	pGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	pRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	pDestroyWindow          = user32.NewProc("DestroyWindow")
	pShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
	pAllocConsole           = kernel32.NewProc("AllocConsole")
	pSetConsoleTitleW       = kernel32.NewProc("SetConsoleTitleW")
	pGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmNull         = 0x0000
	wmCommand      = 0x0111
	wmLButtonUp    = 0x0202
	wmRButtonUp    = 0x0205
	wmContextMenu  = 0x007B
	wmApp          = 0x8000
	wmTray         = wmApp + 1
	nimAdd         = 0
	nimModify      = 1
	nimDelete      = 2
	nifMessage     = 0x1
	nifIcon        = 0x2
	nifTip         = 0x4
	nifInfo        = 0x10
	niifInfo       = 0x1
	niifWarning    = 0x2
	mfString       = 0x0
	mfChecked      = 0x8
	mfSeparator    = 0x800
	mfGrayed       = 0x1
	tpmReturnCmd   = 0x0100
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
	imageIcon      = 1
	smCxSmIcon     = 49
	smCySmIcon     = 50
	cmdOpen        = 1
	cmdAutostart   = 2
	cmdQuit        = 3
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type msgT struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	ptX, ptY int32
	lPrivate uint32
}

type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     windows.Handle
}

type winTray struct {
	app        *App
	open       func()
	mu         sync.Mutex
	hwnd       uintptr
	icon       windows.Handle
	lang       string
	taskbarMsg uint32
	closed     bool
}

var theTray *winTray // für den Fenster-Callback

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func (t *winTray) nid() notifyIconData {
	var n notifyIconData
	n.cbSize = uint32(unsafe.Sizeof(n))
	n.hWnd = t.hwnd
	n.uID = 1
	return n
}

func (t *winTray) add() bool {
	n := t.nid()
	n.uFlags = nifMessage | nifIcon | nifTip
	n.uCallbackMessage = wmTray
	n.hIcon = t.icon
	copyUTF16(n.szTip[:], "RelayPing")
	r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&n)))
	return r != 0
}

func (t *winTray) Notify(title, msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.hwnd == 0 {
		return
	}
	n := t.nid()
	n.uFlags = nifInfo
	n.dwInfoFlags = niifWarning
	copyUTF16(n.szInfoTitle[:], title)
	copyUTF16(n.szInfo[:], msg)
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n)))
}

func (t *winTray) SetLang(lang string) {
	t.mu.Lock()
	t.lang = lang
	t.mu.Unlock()
}

func (t *winTray) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	n := t.nid()
	pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&n)))
	hwnd := t.hwnd
	t.mu.Unlock()
	pPostMessageW.Call(hwnd, wmClose, 0, 0)
}

func (t *winTray) label(de, en string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lang == "en" {
		return en
	}
	return de
}

func (t *winTray) menu() {
	m, _, _ := pCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer pDestroyMenu.Call(m)
	add := func(flags uintptr, id uintptr, text string) {
		p, _ := windows.UTF16PtrFromString(text)
		pAppendMenuW.Call(m, flags, id, uintptr(unsafe.Pointer(p)))
	}
	add(mfString, cmdOpen, t.label("RelayPing öffnen", "Open RelayPing"))
	if on, ok := autostartEnabled(); ok {
		f := uintptr(mfString)
		if on {
			f |= mfChecked
		}
		add(f, cmdAutostart, t.label("Mit Windows starten", "Start with Windows"))
	}
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	add(mfString, cmdQuit, t.label("Beenden", "Quit"))
	var pt struct{ x, y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(t.hwnd)
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmReturnCmd|tpmRightButton|tpmBottomAlign, uintptr(pt.x), uintptr(pt.y), 0, t.hwnd, 0)
	pPostMessageW.Call(t.hwnd, wmNull, 0, 0)
	switch cmd {
	case cmdOpen:
		go t.open()
	case cmdAutostart:
		on, _ := autostartEnabled()
		if err := setAutostart(!on); err != nil {
			t.app.log.Printf("Autostart: %v", err)
		}
		go t.app.pushState()
	case cmdQuit:
		go t.app.Quit()
	}
}

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	t := theTray
	switch {
	case t != nil && msg == wmTray:
		switch lParam & 0xFFFF {
		case wmLButtonUp:
			go t.open()
		case wmRButtonUp, wmContextMenu:
			t.menu()
		}
		return 0
	case t != nil && t.taskbarMsg != 0 && uint32(msg) == t.taskbarMsg:
		t.add() // Explorer wurde neu gestartet
		return 0
	case msg == wmClose:
		pDestroyWindow.Call(hwnd)
		return 0
	case msg == wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func startTray(app *App, open func()) (Tray, error) {
	t := &winTray{app: app, open: open, lang: app.store.Get().Lang}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		h, _, e := pGetModuleHandleW.Call(0)
		if h == 0 {
			ready <- fmt.Errorf("GetModuleHandle: %v", e)
			return
		}
		hinst := windows.Handle(h)
		cls, _ := windows.UTF16PtrFromString("RelayPingTray")
		wc := wndClassEx{lpfnWndProc: syscall.NewCallback(wndProc), hInstance: hinst, lpszClassName: cls}
		wc.cbSize = uint32(unsafe.Sizeof(wc))
		if r, _, e := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			ready <- fmt.Errorf("RegisterClassEx: %v", e)
			return
		}
		title, _ := windows.UTF16PtrFromString("RelayPing")
		hwnd, _, e := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)), 0, 0, 0, 0, 0, 0, 0, uintptr(hinst), 0)
		if hwnd == 0 {
			ready <- fmt.Errorf("CreateWindowEx: %v", e)
			return
		}
		cx, _, _ := pGetSystemMetrics.Call(smCxSmIcon)
		cy, _, _ := pGetSystemMetrics.Call(smCySmIcon)
		icon, _, _ := pLoadImageW.Call(uintptr(hinst), 1, imageIcon, cx, cy, 0)
		if icon == 0 {
			icon, _, _ = pLoadIconW.Call(0, 32512) // IDI_APPLICATION
		}
		tbName, _ := windows.UTF16PtrFromString("TaskbarCreated")
		tb, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tbName)))
		t.hwnd, t.icon, t.taskbarMsg = hwnd, windows.Handle(icon), uint32(tb)
		theTray = t
		if !t.add() {
			ready <- errors.New("Shell_NotifyIcon fehlgeschlagen")
			return
		}
		ready <- nil
		var m msgT
		for {
			r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 {
				return
			}
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return t, nil
}

// showConsole öffnet ein Konsolenfenster (nur wenn das Taskleisten-Symbol fehlt).
func showConsole(app *App, url string) {
	pAllocConsole.Call()
	windows.SetConsoleOutputCP(65001)
	if p, err := windows.UTF16PtrFromString("RelayPing"); err == nil {
		pSetConsoleTitleW.Call(uintptr(unsafe.Pointer(p)))
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
	fmt.Println("RelayPing " + version + " – inoffizielles Tool, nicht mit Mullvad VPN AB oder GL.iNet verbunden")
	if url != "" {
		fmt.Println("Oberfläche: " + url)
	}
	fmt.Println("Daten:      " + app.store.dir)
	fmt.Println()
	fmt.Println("Dieses Fenster offen lassen. Schließen beendet das Programm.")
}

var instanceMutex windows.Handle

func acquireSingleInstance() bool {
	name, _ := windows.UTF16PtrFromString("Local\\RelayPing-Instanz")
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return false
		}
		return true
	}
	instanceMutex = h
	return true
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func exePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

// autostartEnabled: (an, verfügbar)
func autostartEnabled() (bool, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, true
	}
	defer k.Close()
	v, _, err := k.GetStringValue("RelayPing")
	if err != nil {
		return false, true
	}
	return strings.Contains(strings.ToLower(v), strings.ToLower(exePath())), true
}

func setAutostart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		err := k.DeleteValue("RelayPing")
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	p := exePath()
	if p == "" {
		return errors.New("Pfad der .exe unbekannt")
	}
	return k.SetStringValue("RelayPing", `"`+p+`" --hidden`)
}

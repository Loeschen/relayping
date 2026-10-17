package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Meldungen aufs Handy über ntfy (App „ntfy“, Thema frei wählbar, auch eigener Server)
// oder einen eigenen Telegram-Bot. Zugangsdaten liegen mit Windows-DPAPI verschlüsselt
// in relayping.json. Gesendet wird nur, was in den Einstellungen angehakt ist.

var pushCats = []string{"ausfall", "kurz", "dns", "warnung", "wechsel", "update"}

var (
	reNtfyURL  = regexp.MustCompile(`^https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?/[A-Za-z0-9_\-]{1,64}$`)
	reTgToken  = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_\-]{30,50}$`)
	reTgChatID = regexp.MustCompile(`^-?[0-9]{3,20}$`)
)

type PushState struct {
	Mode    string          `json:"mode"` // "", ntfy, telegram
	Target  string          `json:"target"`
	Cats    map[string]bool `json:"cats"`
	HasCred bool            `json:"has_cred"`
	Last    string          `json:"last,omitempty"`
	LastErr string          `json:"last_error,omitempty"`
	Sent    int             `json:"sent"`
}

type Pusher struct {
	app     *App
	mu      sync.Mutex
	last    map[string]time.Time
	held    map[string][]string // in der Sperrzeit gesammelt
	lastMsg string
	lastErr string
	sent    int
}

func newPusher(a *App) *Pusher {
	return &Pusher{app: a, last: map[string]time.Time{}, held: map[string][]string{}}
}

// push sendet eine Meldung aufs Handy, sofern die Kategorie eingeschaltet ist.
// Pro Kategorie höchstens eine Nachricht je Minute; was dazwischen kommt, wird gebündelt.
func (a *App) push(cat, title, msg string) {
	if a.pusher == nil {
		return
	}
	c := a.store.Get()
	if c.PushMode == "" || !c.PushCats[cat] {
		return
	}
	p := a.pusher
	p.mu.Lock()
	if time.Since(p.last[cat]) < time.Minute {
		if len(p.held[cat]) < 20 {
			p.held[cat] = append(p.held[cat], msg)
		}
		first := len(p.held[cat]) == 1
		p.mu.Unlock()
		if first {
			go func() {
				time.Sleep(time.Minute - time.Since(p.last[cat]) + time.Second)
				p.mu.Lock()
				h := p.held[cat]
				p.held[cat] = nil
				p.last[cat] = time.Now()
				p.mu.Unlock()
				if len(h) > 0 {
					_ = p.send(title, strings.Join(h, "\n"))
				}
			}()
		}
		return
	}
	p.last[cat] = time.Now()
	p.mu.Unlock()
	go func() { _ = p.send(title, msg) }()
}

func (p *Pusher) send(title, msg string) error {
	a := p.app
	c := a.store.Get()
	secret, err := unprotectSecret(c.PushSecret)
	if err != nil || secret == "" {
		return p.result("", errors.New(a.tr("Zugangsdaten fehlen", "credentials missing")))
	}
	cl := &http.Client{Timeout: 15 * time.Second}
	var req *http.Request
	switch c.PushMode {
	case "ntfy":
		if !reNtfyURL.MatchString(secret) {
			return p.result("", errors.New(a.tr("ntfy-Adresse ungültig", "invalid ntfy address")))
		}
		req, _ = http.NewRequest(http.MethodPost, secret, strings.NewReader(msg))
		req.Header.Set("Title", asciiHeader(title))
		req.Header.Set("Tags", "satellite")
	case "telegram":
		tok, chat, ok := strings.Cut(secret, "|")
		if !ok || !reTgToken.MatchString(tok) || !reTgChatID.MatchString(chat) {
			return p.result("", errors.New(a.tr("Telegram-Angaben ungültig", "invalid Telegram details")))
		}
		form := url.Values{"chat_id": {chat}, "text": {title + "\n" + msg}, "disable_web_page_preview": {"true"}}
		req, _ = http.NewRequest(http.MethodPost, "https://api.telegram.org/bot"+tok+"/sendMessage", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
		return nil
	}
	req.Header.Set("User-Agent", "RelayPing/"+version)
	resp, err := cl.Do(req)
	if err != nil {
		// Fehlermeldungen können die Adresse mit dem Telegram-Schlüssel enthalten – nicht weitergeben
		return p.result("", errors.New(a.tr("Senden fehlgeschlagen (keine Verbindung)", "sending failed (no connection)")))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 {
		t := strings.TrimSpace(string(body))
		if len(t) > 120 {
			t = t[:120]
		}
		return p.result("", fmt.Errorf(a.tr("Senden fehlgeschlagen: HTTP %d %s", "sending failed: HTTP %d %s"), resp.StatusCode, t))
	}
	return p.result(title+": "+msg, nil)
}

func asciiHeader(s string) string {
	// HTTP-Kopfzeilen dürfen keine Umlaute enthalten – ntfy versteht RFC-2047
	for _, r := range s {
		if r > 126 {
			return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}

func (p *Pusher) result(msg string, err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.lastErr = err.Error()
		p.app.log.Printf("Handy-Meldung: %v", err)
		return err
	}
	p.lastErr, p.lastMsg = "", msg
	p.sent++
	return nil
}

func (p *Pusher) State() PushState {
	c := p.app.store.Get()
	st := PushState{Mode: c.PushMode, Cats: map[string]bool{}, HasCred: c.PushSecret != ""}
	for _, k := range pushCats {
		st.Cats[k] = c.PushCats[k]
	}
	if c.PushMode == "ntfy" && c.PushSecret != "" {
		if s, err := unprotectSecret(c.PushSecret); err == nil {
			st.Target = s // Thema-Adresse zeigen, damit man sie in der App abonnieren kann
		}
	}
	if c.PushMode == "telegram" && c.PushSecret != "" {
		if s, err := unprotectSecret(c.PushSecret); err == nil {
			_, chat, _ := strings.Cut(s, "|")
			st.Target = "Chat " + chat
		}
	}
	p.mu.Lock()
	st.Last, st.LastErr, st.Sent = p.lastMsg, p.lastErr, p.sent
	p.mu.Unlock()
	return st
}

// Configure speichert die Einstellungen. secret leer und keep = alte Zugangsdaten behalten.
func (p *Pusher) Configure(mode, ntfyURL, tgToken, tgChat string, cats map[string]bool, keep bool) error {
	a := p.app
	secret := ""
	switch mode {
	case "":
	case "ntfy":
		ntfyURL = strings.TrimSpace(ntfyURL)
		if ntfyURL == "" && keep {
			break
		}
		if !reNtfyURL.MatchString(ntfyURL) {
			return errors.New(a.tr("Bitte eine ntfy-Adresse wie https://ntfy.sh/meinthema eingeben (Thema nur Buchstaben, Ziffern, - und _).",
				"Please enter an ntfy address like https://ntfy.sh/mytopic (topic only letters, digits, - and _)."))
		}
		secret = ntfyURL
	case "telegram":
		tgToken, tgChat = strings.TrimSpace(tgToken), strings.TrimSpace(tgChat)
		if tgToken == "" && tgChat == "" && keep {
			break
		}
		if !reTgToken.MatchString(tgToken) || !reTgChatID.MatchString(tgChat) {
			return errors.New(a.tr("Bot-Token (von @BotFather) und Chat-ID prüfen.", "Check bot token (from @BotFather) and chat ID."))
		}
		secret = tgToken + "|" + tgChat
	default:
		return errors.New("unbekannte Art")
	}
	enc := ""
	if secret != "" {
		var err error
		if enc, err = protectSecret(secret); err != nil {
			return err
		}
	}
	clean := map[string]bool{}
	for _, k := range pushCats {
		if cats[k] {
			clean[k] = true
		}
	}
	return a.store.Update(func(c *Config) {
		if mode != c.PushMode || secret != "" || mode == "" {
			c.PushSecret = enc
		}
		c.PushMode, c.PushCats = mode, clean
	})
}

func (p *Pusher) Test() error {
	a := p.app
	if a.store.Get().PushMode == "" {
		return errors.New(a.tr("Keine Handy-Meldungen eingerichtet", "No phone notifications set up"))
	}
	return p.send("RelayPing", a.tr("Test: Meldungen aufs Handy funktionieren.", "Test: phone notifications work."))
}

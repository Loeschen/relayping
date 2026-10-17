package main

// Tray ist das Symbol im Infobereich der Taskleiste (nur Windows).
type Tray interface {
	Notify(title, msg string)
	SetLang(lang string)
	SetStatus(level int, tip string) // 0 ok, 1 Warnung, 2 Problem, -1 unbekannt
	Close()
}

type noTray struct{}

func (noTray) Notify(title, msg string) {}
func (noTray) SetLang(string)           {}
func (noTray) SetStatus(int, string)    {}
func (noTray) Close()                   {}

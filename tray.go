package main

// Tray ist das Symbol im Infobereich der Taskleiste (nur Windows).
type Tray interface {
	Notify(title, msg string)
	SetLang(lang string)
	Close()
}

type noTray struct{}

func (noTray) Notify(title, msg string) {}
func (noTray) SetLang(string)           {}
func (noTray) Close()                   {}

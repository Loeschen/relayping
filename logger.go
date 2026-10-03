package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger schreibt eine kleine Protokolldatei neben die .exe (max. ~1 MB, dann rotiert).
type Logger struct {
	mu   sync.Mutex
	path string
}

func newLogger(path string) *Logger { return &Logger{path: path} }

func (l *Logger) Printf(format string, args ...any) {
	if l == nil {
		return
	}
	line := time.Now().Format("2006-01-02 15:04:05 ") + fmt.Sprintf(format, args...) + "\r\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	if fi, err := os.Stat(l.path); err == nil && fi.Size() > 1<<20 {
		_ = os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	f.WriteString(line)
	f.Close()
}

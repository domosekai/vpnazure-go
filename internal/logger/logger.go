// Turnout
// Released under MIT License
// Copyright (c) 2022 Yihong Wu

// Custom logger safe to rotate

package logger

import (
	"log"
	"os"
	"sync"
)

type Logger struct {
	logger *log.Logger
	file   *os.File
	rw     sync.RWMutex
}

func (l *Logger) Open(filename string, append bool) {
	l.rw.Lock()
	defer l.rw.Unlock()
	// Close current file first
	if l.file != nil {
		l.file.Close()
	}
	if filename != "" {
		var err error
		if append {
			l.file, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		} else {
			l.file, err = os.Create(filename)
		}
		if err != nil {
			log.Fatalf("Failed to create log file. Error: %s", err)
		}
		l.logger = log.New(l.file, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	} else {
		l.logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

func (l *Logger) Printf(format string, v ...any) {
	l.rw.RLock()
	l.logger.Printf(format, v...)
	l.rw.RUnlock()
}

func (l *Logger) Print(v ...any) {
	l.rw.RLock()
	l.logger.Print(v...)
	l.rw.RUnlock()
}

func (l *Logger) Println(v ...any) {
	l.rw.RLock()
	l.logger.Println(v...)
	l.rw.RUnlock()
}

// Print fancier log for sessions.
// Stage: 1 for starting, 2 for established, 3 for closing.
func (l *Logger) PrintSessionf(format string, num uint64, sType byte, stage int, v ...any) {
	l.rw.RLock()
	stages := [4]string{
		"       ",
		" *     ",
		"   *   ",
		"     * ",
	}
	l.logger.Printf("%c %5d:"+stages[stage]+format, append([]any{sType, num}, v...)...)
	l.rw.RUnlock()
}

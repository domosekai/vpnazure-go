// Reacts on system signals

//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func listenSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGUSR2)
	for sig := range sigs {
		switch sig {
		case syscall.SIGHUP:
			lg.Println("Received signal to reload files")

			// Read DNS suffix from file
			if n := suffixes.read(*suffixFile); n > 0 {
				lg.Printf("Loaded %d suffixes", n)
			} else {
				log.Fatalf("At least 1 DNS suffix is needed")
			}

			// Read server credentials
			if n := auths.read(*authFile); n > 0 {
				lg.Printf("Loaded %d server credentials", n)
			} else {
				log.Fatalf("At least 1 server credential is needed")
			}

			// Remove outdated server control sessions
			sessions.cleanupServers()
		case syscall.SIGUSR2:
			if *logFile == "" {
				break
			}
			lg.Println("Received signal to reopen log file")
			lg.Open(*logFile, false)
		}
	}
}

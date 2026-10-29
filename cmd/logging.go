package main

import (
	"log/slog"
	"os"
)

// logLevel controls the default slog logger used throughout the program. It
// starts at Info and is lowered to Debug by the --debug flag.
var logLevel = new(slog.LevelVar)

var debug bool

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))
}

// setupLogging applies the logging flags; it must run after flag parsing.
func setupLogging() {
	if debug {
		logLevel.Set(slog.LevelDebug)
	}
}

// fatal logs msg at Error level and exits with status 1.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

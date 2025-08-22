package logger

import (
	"log/slog"
	"os"
)

// Logger wraps slog.Logger with additional functionality.
type Logger struct {
	*slog.Logger
}

// New creates a new structured logger.
func New() *Logger {
	level := slog.LevelInfo
	if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
		switch envLevel {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}

	format := os.Getenv("LOG_FORMAT")
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch format {
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

// WithCVE adds CVE ID to the logger context.
func (l *Logger) WithCVE(cveID string) *slog.Logger {
	return l.With(slog.String("cve_id", cveID))
}

// WithService adds service name to the logger context.
func (l *Logger) WithService(service string) *slog.Logger {
	return l.With(slog.String("service", service))
}

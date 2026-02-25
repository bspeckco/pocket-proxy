package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = [...]string{"DBG", "INF", "WRN", "ERR"}

func (l Level) String() string {
	if int(l) < len(levelNames) {
		return levelNames[l]
	}
	return "???"
}

// ParseLevel parses a level string (case-insensitive).
// Valid values: "debug", "info", "warn", "error".
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q (valid: debug, info, warn, error)", s)
	}
}

type Logger struct {
	level Level
	mu    sync.Mutex
	out   io.Writer
	file  *os.File // non-nil if we opened a log file
}

type Options struct {
	Level   Level
	LogFile string // optional file path; empty means stderr only
}

// New creates a logger. Output always goes to stderr; if LogFile is set,
// output is also written to that file.
func New(opts Options) (*Logger, error) {
	l := &Logger{level: opts.Level}

	if opts.LogFile != "" {
		f, err := os.OpenFile(opts.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log file: %w", err)
		}
		l.file = f
		l.out = io.MultiWriter(os.Stderr, f)
	} else {
		l.out = os.Stderr
	}

	return l, nil
}

// Nop returns a logger that discards everything. Useful in tests.
func Nop() *Logger {
	return &Logger{level: LevelError + 1, out: io.Discard}
}

func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) log(level Level, msg string, args ...any) {
	if level < l.level {
		return
	}
	ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	line := fmt.Sprintf("%s %s %s\n", ts, level, fmt.Sprintf(msg, args...))
	l.mu.Lock()
	l.out.Write([]byte(line))
	l.mu.Unlock()
}

func (l *Logger) Debug(msg string, args ...any) { l.log(LevelDebug, msg, args...) }
func (l *Logger) Info(msg string, args ...any)  { l.log(LevelInfo, msg, args...) }
func (l *Logger) Warn(msg string, args ...any)  { l.log(LevelWarn, msg, args...) }
func (l *Logger) Error(msg string, args ...any) { l.log(LevelError, msg, args...) }

// Fatal logs at error level and exits.
func (l *Logger) Fatal(msg string, args ...any) {
	l.log(LevelError, msg, args...)
	os.Exit(1)
}

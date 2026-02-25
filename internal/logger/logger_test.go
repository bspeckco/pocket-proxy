package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
		err   bool
	}{
		{"debug", LevelDebug, false},
		{"DEBUG", LevelDebug, false},
		{"info", LevelInfo, false},
		{"Info", LevelInfo, false},
		{"warn", LevelWarn, false},
		{"WARN", LevelWarn, false},
		{"error", LevelError, false},
		{"Error", LevelError, false},
		{"invalid", LevelInfo, true},
		{"", LevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseLevel(tt.input)
			if (err != nil) != tt.err {
				t.Errorf("ParseLevel(%q) error = %v, want error = %v", tt.input, err, tt.err)
			}
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{level: LevelWarn, out: &buf}

	l.Debug("debug msg")
	l.Info("info msg")
	l.Warn("warn msg")
	l.Error("error msg")

	output := buf.String()
	if strings.Contains(output, "debug msg") {
		t.Error("debug message should be filtered at warn level")
	}
	if strings.Contains(output, "info msg") {
		t.Error("info message should be filtered at warn level")
	}
	if !strings.Contains(output, "warn msg") {
		t.Error("warn message should be present at warn level")
	}
	if !strings.Contains(output, "error msg") {
		t.Error("error message should be present at warn level")
	}
}

func TestLogFormat(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{level: LevelDebug, out: &buf}

	l.Info("hello %s", "world")

	line := buf.String()
	if !strings.Contains(line, "INF") {
		t.Errorf("expected INF level tag, got %q", line)
	}
	if !strings.Contains(line, "hello world") {
		t.Errorf("expected formatted message, got %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Error("expected newline at end")
	}
}

func TestLogToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := New(Options{Level: LevelInfo, LogFile: path})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	l.Info("file log entry")
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if !strings.Contains(string(data), "file log entry") {
		t.Errorf("expected log entry in file, got %q", data)
	}
}

func TestNopLogger(t *testing.T) {
	l := Nop()
	// Should not panic
	l.Debug("ignored")
	l.Info("ignored")
	l.Warn("ignored")
	l.Error("ignored")
}

func TestLevelString(t *testing.T) {
	if LevelDebug.String() != "DBG" {
		t.Errorf("expected DBG, got %s", LevelDebug.String())
	}
	if LevelInfo.String() != "INF" {
		t.Errorf("expected INF, got %s", LevelInfo.String())
	}
	if LevelWarn.String() != "WRN" {
		t.Errorf("expected WRN, got %s", LevelWarn.String())
	}
	if LevelError.String() != "ERR" {
		t.Errorf("expected ERR, got %s", LevelError.String())
	}
}

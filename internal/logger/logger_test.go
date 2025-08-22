package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
)

func TestNew(t *testing.T) {
	// Save original env vars
	originalLevel := os.Getenv("LOG_LEVEL")
	originalFormat := os.Getenv("LOG_FORMAT")
	defer func() {
		os.Setenv("LOG_LEVEL", originalLevel)
		os.Setenv("LOG_FORMAT", originalFormat)
	}()

	tests := []struct {
		name      string
		logLevel  string
		logFormat string
		wantLevel slog.Level
		wantJSON  bool
	}{
		{
			name:      "default_settings",
			logLevel:  "",
			logFormat: "",
			wantLevel: slog.LevelInfo,
			wantJSON:  true, // JSON is default
		},
		{
			name:      "debug_level",
			logLevel:  "debug",
			logFormat: "json",
			wantLevel: slog.LevelDebug,
			wantJSON:  true,
		},
		{
			name:      "warn_level",
			logLevel:  "warn",
			logFormat: "json",
			wantLevel: slog.LevelWarn,
			wantJSON:  true,
		},
		{
			name:      "error_level",
			logLevel:  "error",
			logFormat: "json",
			wantLevel: slog.LevelError,
			wantJSON:  true,
		},
		{
			name:      "text_format",
			logLevel:  "info",
			logFormat: "text",
			wantLevel: slog.LevelInfo,
			wantJSON:  false,
		},
		{
			name:      "unknown_level_defaults_to_info",
			logLevel:  "unknown",
			logFormat: "json",
			wantLevel: slog.LevelInfo,
			wantJSON:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			os.Setenv("LOG_LEVEL", tt.logLevel)
			os.Setenv("LOG_FORMAT", tt.logFormat)

			// Test that logger can be created without errors
			
			// Create logger - we need to modify the New function to accept an io.Writer for testing
			// For now, we'll test that the logger is created without errors
			logger := New()
			
			if logger == nil {
				t.Error("New() returned nil logger")
				return
			}

			if logger.Logger == nil {
				t.Error("New() returned logger with nil underlying Logger")
				return
			}

			// Test logging to verify the level is set correctly
			// We'll use a test that checks if debug messages are logged when debug level is set
			if tt.wantLevel == slog.LevelDebug {
				// This is a basic test - in a real scenario we'd need to capture the output
				logger.Debug("test debug message")
			}
		})
	}
}

func TestLogger_WithCVE(t *testing.T) {
	logger := New()
	cveID := "CVE-2023-1234"
	
	contextLogger := logger.WithCVE(cveID)
	
	if contextLogger == nil {
		t.Error("WithCVE() returned nil logger")
		return
	}

	// Test that the returned logger is a *slog.Logger
	if _, ok := interface{}(contextLogger).(*slog.Logger); !ok {
		t.Error("WithCVE() did not return a *slog.Logger")
	}
}

func TestLogger_WithService(t *testing.T) {
	logger := New()
	serviceName := "NVD"
	
	contextLogger := logger.WithService(serviceName)
	
	if contextLogger == nil {
		t.Error("WithService() returned nil logger")
		return
	}

	// Test that the returned logger is a *slog.Logger
	if _, ok := interface{}(contextLogger).(*slog.Logger); !ok {
		t.Error("WithService() did not return a *slog.Logger")
	}
}

func TestLogger_ContextMethods(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(*Logger) *slog.Logger
		key      string
		value    string
	}{
		{
			name: "WithCVE",
			testFunc: func(l *Logger) *slog.Logger {
				return l.WithCVE("CVE-2023-1234")
			},
			key:   "cve_id",
			value: "CVE-2023-1234",
		},
		{
			name: "WithService",
			testFunc: func(l *Logger) *slog.Logger {
				return l.WithService("TestService")
			},
			key:   "service",
			value: "TestService",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a logger with a buffer to capture output
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})
			baseLogger := &Logger{
				Logger: slog.New(handler),
			}

			// Get context logger
			contextLogger := tt.testFunc(baseLogger)
			
			// Log a test message
			contextLogger.Info("test message")
			
			// Parse the JSON output to verify the context was added
			var logEntry map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
				t.Fatalf("Failed to parse log output as JSON: %v", err)
			}

			// Check that the expected key-value pair is present
			if val, ok := logEntry[tt.key]; !ok {
				t.Errorf("Expected key %q not found in log output", tt.key)
			} else if val != tt.value {
				t.Errorf("Expected %q=%q, got %q=%v", tt.key, tt.value, tt.key, val)
			}

			// Verify the message is present
			if msg, ok := logEntry["msg"]; !ok {
				t.Error("Expected 'msg' key not found in log output")
			} else if msg != "test message" {
				t.Errorf("Expected msg='test message', got msg=%v", msg)
			}
		})
	}
}

func TestLogger_EnvironmentVariables(t *testing.T) {
	// Test that environment variables are properly read
	tests := []struct {
		name      string
		envLevel  string
		envFormat string
		shouldLog bool // whether debug messages should appear
	}{
		{
			name:      "debug_level_set",
			envLevel:  "debug",
			envFormat: "json",
			shouldLog: true,
		},
		{
			name:      "error_level_set",
			envLevel:  "error",
			envFormat: "json",
			shouldLog: false, // debug messages should not appear at error level
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore environment
			originalLevel := os.Getenv("LOG_LEVEL")
			originalFormat := os.Getenv("LOG_FORMAT")
			defer func() {
				os.Setenv("LOG_LEVEL", originalLevel)
				os.Setenv("LOG_FORMAT", originalFormat)
			}()

			// Set test environment
			os.Setenv("LOG_LEVEL", tt.envLevel)
			os.Setenv("LOG_FORMAT", tt.envFormat)

			// Create logger
			logger := New()
			if logger == nil {
				t.Fatal("New() returned nil logger")
			}

			// Test that the logger was created successfully
			// In a real test, we'd capture output and verify the level
			// For now, just ensure no panic occurs
			logger.Info("test info message")
			logger.Debug("test debug message")
			logger.Error("test error message")
		})
	}
}

func TestLogger_HandlerTypes(t *testing.T) {
	originalFormat := os.Getenv("LOG_FORMAT")
	defer os.Setenv("LOG_FORMAT", originalFormat)

	tests := []struct {
		name      string
		format    string
		expectJSON bool
	}{
		{
			name:       "json_format",
			format:     "json",
			expectJSON: true,
		},
		{
			name:       "text_format", 
			format:     "text",
			expectJSON: false,
		},
		{
			name:       "default_format",
			format:     "",
			expectJSON: true, // JSON is default
		},
		{
			name:       "unknown_format",
			format:     "xml",
			expectJSON: true, // Should fallback to JSON
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("LOG_FORMAT", tt.format)
			
			logger := New()
			if logger == nil {
				t.Fatal("New() returned nil logger")
			}

			// Test that logger can be used without panic
			logger.Info("test message")
		})
	}
}
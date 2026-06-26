package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

const (
	defaultPluginLogPath = "/run/swarm-external-secrets/plugin.log"
	defaultMaxLogSize    = int64(10 * 1024 * 1024) // 10MB
)

// cappedFileWriter appends to a log file and rotates it when max size is exceeded.
type cappedFileWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
}

func newCappedFileWriter(path string, maxBytes int64) (*cappedFileWriter, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxLogSize
	}

	resolvedPath, err := validateLogPath(path)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(resolvedPath), 0o750); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	// #nosec G304 -- path is the configured plugin log destination after basic path validation.
	f, err := os.OpenFile(resolvedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	return &cappedFileWriter{path: resolvedPath, maxBytes: maxBytes, file: f}, nil
}

func (w *cappedFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.rotateIfNeeded(int64(len(p))); err != nil {
		return 0, err
	}

	return w.file.Write(p)
}

func (w *cappedFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}

func (w *cappedFileWriter) rotateIfNeeded(incoming int64) error {
	info, err := w.file.Stat()
	if err != nil {
		return fmt.Errorf("stat log file: %w", err)
	}

	if info.Size()+incoming <= w.maxBytes {
		return nil
	}

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close log file for rotation: %w", err)
	}

	rotatedPath := w.path + ".1"
	if err := os.Remove(rotatedPath); err != nil && !os.IsNotExist(err) {
		if reopenErr := w.reopenActiveFile(); reopenErr != nil {
			return fmt.Errorf("remove previous rotated log: %w (reopen active log failed: %v)", err, reopenErr)
		}
		return fmt.Errorf("remove previous rotated log: %w", err)
	}

	if err := os.Rename(w.path, rotatedPath); err != nil && !os.IsNotExist(err) {
		if reopenErr := w.reopenActiveFile(); reopenErr != nil {
			return fmt.Errorf("rotate log file: %w (reopen active log failed: %v)", err, reopenErr)
		}
		return fmt.Errorf("rotate log file: %w", err)
	}

	if err := w.reopenActiveFile(); err != nil {
		return fmt.Errorf("reopen log file after rotation: %w", err)
	}

	return nil
}

func (w *cappedFileWriter) reopenActiveFile() error {
	// #nosec G304 -- writer path is validated during construction in newCappedFileWriter.
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w.file = f
	return nil
}

func ConfigureLogger(debugFlag bool) io.Closer {
	level := configuredLogLevel(debugFlag)
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	logPath := utils.GetEnvOrDefault("PLUGIN_LOG_PATH", defaultPluginLogPath)
	writer, err := newCappedFileWriter(logPath, defaultMaxLogSize)
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Warnf("failed to initialize file logging at %s: %v", logPath, err)
		return nil
	}

	log.SetOutput(io.MultiWriter(os.Stderr, writer))
	log.Infof("plugin logging configured with path=%s level=%s max_size_mb=%d", logPath, level.String(), defaultMaxLogSize/(1024*1024))
	return writer
}

func configuredLogLevel(debugFlag bool) log.Level {
	if raw, ok := os.LookupEnv("LOG_LEVEL"); ok {
		return parsePluginLogLevel(raw)
	}

	if debugFlag {
		return log.DebugLevel
	}

	return log.DebugLevel
}

func parsePluginLogLevel(raw string) log.Level {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if numericLevel, err := strconv.Atoi(normalized); err == nil {
		level, err := parseIntegerLogLevel(numericLevel)
		if err != nil {
			log.Errorf("invalid LOG_LEVEL=%q: expected integer 0-6 or log level name; defaulting to debug", raw)
			return log.DebugLevel
		}
		return level
	}

	parsed, err := log.ParseLevel(normalized)
	if err != nil {
		log.Errorf("invalid LOG_LEVEL=%q: expected integer 0-6 or log level name; defaulting to debug", raw)
		return log.DebugLevel
	}
	return parsed
}

func parseIntegerLogLevel(n int) (log.Level, error) {
	if n < int(log.PanicLevel) || n > int(log.TraceLevel) {
		return log.DebugLevel, fmt.Errorf("log level %d outside range 0-6", n)
	}
	return log.Level(n), nil
}

func validateLogPath(path string) (string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "." || cleanPath == string(filepath.Separator) {
		return "", fmt.Errorf("invalid log path: %q", path)
	}

	return cleanPath, nil
}

package export

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RotateWriter implements io.WriteCloser and provides automatic file splitting
// based on maximum size and/or time duration.
type RotateWriter struct {
	mu              sync.Mutex
	basePath        string
	maxSize         int64
	maxDuration     time.Duration
	headerGenerator func() []byte
	onRotate        func(closedPath string)

	currentFile *os.File
	currentSize int64
	startTime   time.Time
	partIndex   int
}

// RotateWriterConfig holds configuration options for the RotateWriter.
type RotateWriterConfig struct {
	BasePath        string
	MaxSize         int64         // Max size in bytes before rotating (0 = no size rotation)
	MaxDuration     time.Duration // Max duration before rotating (0 = no time rotation)
	HeaderGenerator func() []byte // Callback to generate standard header bytes for each new file part
	OnRotate        func(closedPath string) // Callback invoked asynchronously when a file part is closed
}

// NewRotateWriter creates and opens the initial file part.
func NewRotateWriter(cfg RotateWriterConfig) (*RotateWriter, error) {
	if cfg.BasePath == "" {
		return nil, fmt.Errorf("base path is empty")
	}

	// Ensure parent directory exists
	dir := filepath.Dir(cfg.BasePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create capture directory: %w", err)
	}

	w := &RotateWriter{
		basePath:        cfg.BasePath,
		maxSize:         cfg.MaxSize,
		maxDuration:     cfg.MaxDuration,
		headerGenerator: cfg.HeaderGenerator,
		onRotate:        cfg.OnRotate,
	}

	if err := w.openNextPart(); err != nil {
		return nil, err
	}

	return w, nil
}

// Write writes data to the active file part. It automatically triggers rotation
// if writing would exceed the size limit or if the time limit is reached.
func (w *RotateWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentFile == nil {
		return 0, fmt.Errorf("writer is closed")
	}

	// Check if time-based rotation is triggered
	timeTriggered := w.maxDuration > 0 && time.Since(w.startTime) >= w.maxDuration
	// Check if size-based rotation is triggered
	sizeTriggered := w.maxSize > 0 && (w.currentSize+int64(len(p))) > w.maxSize

	if timeTriggered || sizeTriggered {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err = w.currentFile.Write(p)
	w.currentSize += int64(n)
	return n, err
}

// Close closes the current active file part.
func (w *RotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentFile == nil {
		return nil
	}

	err := w.currentFile.Close()
	closedPath := w.getPartPath(w.partIndex)
	w.currentFile = nil

	// Trigger final rotate callback
	if w.onRotate != nil {
		go w.onRotate(closedPath)
	}

	return err
}

// rotateLocked rotates the active file part. Caller must hold w.mu.
func (w *RotateWriter) rotateLocked() error {
	closedPath := w.getPartPath(w.partIndex)
	if err := w.currentFile.Close(); err != nil {
		return fmt.Errorf("close active part during rotate: %w", err)
	}

	// Invoke callback asynchronously
	if w.onRotate != nil {
		go w.onRotate(closedPath)
	}

	w.partIndex++
	return w.openNextPart()
}

func (w *RotateWriter) openNextPart() error {
	path := w.getPartPath(w.partIndex)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create part file %q: %w", path, err)
	}

	w.currentFile = f
	w.currentSize = 0
	w.startTime = time.Now()

	// Write custom headers if provided
	if w.headerGenerator != nil {
		header := w.headerGenerator()
		if len(header) > 0 {
			n, err := f.Write(header)
			if err != nil {
				f.Close()
				return fmt.Errorf("write header to part file %q: %w", path, err)
			}
			w.currentSize += int64(n)
		}
	}

	return nil
}

// getPartPath computes the path for the given part index.
// E.g., if basePath is "/var/log/capture.pcapng":
//   - part 0: "/var/log/capture.pcapng"
//   - part 1: "/var/log/capture_part1.pcapng"
func (w *RotateWriter) getPartPath(index int) string {
	if index == 0 {
		return w.basePath
	}

	ext := filepath.Ext(w.basePath)
	base := strings.TrimSuffix(w.basePath, ext)
	return fmt.Sprintf("%s_part%d%s", base, index, ext)
}

// CurrentFile returns the underlying active file for debugging/testing.
func (w *RotateWriter) CurrentFile() *os.File {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.currentFile
}

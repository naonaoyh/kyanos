package rtcm

import (
	"fmt"
	"os"
	"sync"
)

// RTCMExporter writes raw RTCM frames to a binary .rtcm file.
// It is safe for concurrent use from multiple goroutines.
type RTCMExporter struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// NewRTCMExporter creates a new exporter that writes to the given file path.
// The file is created (or truncated) immediately.
func NewRTCMExporter(path string) (*RTCMExporter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create export file %q: %w", path, err)
	}
	return &RTCMExporter{file: f, path: path}, nil
}

// WriteFrame writes the raw bytes of an RTCM frame to the export file.
// Frames are written sequentially, producing a standard .rtcm binary stream
// that can be replayed with tools like RTKLIB, rtkrcv, or convbin.
func (e *RTCMExporter) WriteFrame(frame *RTCMFrame) error {
	if frame == nil || len(frame.RawBytes) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.file.Write(frame.RawBytes)
	return err
}

// Close flushes and closes the export file.
func (e *RTCMExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		return e.file.Close()
	}
	return nil
}

// Path returns the file path of the export file.
func (e *RTCMExporter) Path() string {
	return e.path
}

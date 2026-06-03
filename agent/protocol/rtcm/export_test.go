package rtcm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRTCMExporter_WriteFrame(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.rtcm")

	exporter, err := NewRTCMExporter(path)
	if err != nil {
		t.Fatalf("NewRTCMExporter error: %v", err)
	}

	// Write a frame with raw bytes
	frame := &RTCMFrame{
		Preamble:    RTCMPreamble,
		MessageType: 1077,
		CRCValid:    true,
		TotalLen:    10,
		RawBytes:    []byte{0xD3, 0x00, 0x04, 0x43, 0x50, 0x00, 0x00, 0xAA, 0xBB, 0xCC},
	}
	if err := exporter.WriteFrame(frame); err != nil {
		t.Fatalf("WriteFrame error: %v", err)
	}

	// Write another frame
	frame2 := &RTCMFrame{
		Preamble:    RTCMPreamble,
		MessageType: 1005,
		CRCValid:    true,
		TotalLen:    6,
		RawBytes:    []byte{0xD3, 0x00, 0x00, 0x3E, 0xD0, 0x00},
	}
	if err := exporter.WriteFrame(frame2); err != nil {
		t.Fatalf("WriteFrame error: %v", err)
	}

	if err := exporter.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Verify file contents
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	expectedLen := len(frame.RawBytes) + len(frame2.RawBytes)
	if len(data) != expectedLen {
		t.Errorf("file size = %d, want %d", len(data), expectedLen)
	}
	// Verify first frame preamble
	if data[0] != 0xD3 {
		t.Errorf("first byte = 0x%02X, want 0xD3", data[0])
	}
	// Verify second frame starts after first
	if data[len(frame.RawBytes)] != 0xD3 {
		t.Errorf("second frame preamble = 0x%02X, want 0xD3", data[len(frame.RawBytes)])
	}
}

func TestRTCMExporter_NilFrame(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.rtcm")

	exporter, err := NewRTCMExporter(path)
	if err != nil {
		t.Fatalf("NewRTCMExporter error: %v", err)
	}

	// Writing nil frame should not error
	if err := exporter.WriteFrame(nil); err != nil {
		t.Errorf("WriteFrame(nil) error: %v", err)
	}

	// Writing frame with empty RawBytes should not error
	if err := exporter.WriteFrame(&RTCMFrame{}); err != nil {
		t.Errorf("WriteFrame(empty) error: %v", err)
	}

	exporter.Close()

	// File should be empty
	data, _ := os.ReadFile(path)
	if len(data) != 0 {
		t.Errorf("file size = %d, want 0 (no frames written)", len(data))
	}
}

func TestRTCMExporter_Path(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output.rtcm")

	exporter, err := NewRTCMExporter(path)
	if err != nil {
		t.Fatalf("NewRTCMExporter error: %v", err)
	}
	defer exporter.Close()

	if exporter.Path() != path {
		t.Errorf("Path() = %q, want %q", exporter.Path(), path)
	}
}

func TestRTCMExporter_InvalidPath(t *testing.T) {
	_, err := NewRTCMExporter("/nonexistent/dir/test.rtcm")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestRTCMFrame_RawBytesStored(t *testing.T) {
	// Build a valid RTCM frame via ParseStream to verify RawBytes is populated
	frameData := buildValidRTCMFrame(1074, 10)
	sb := makeStreamBuffer(frameData)
	parser := &RTCMStreamParser{}

	result := parser.ParseStream(sb, 0)
	if result.ParseState != 2 { // Success
		t.Fatalf("ParseStream state = %d, want Success(2)", result.ParseState)
	}
	frame := result.ParsedMessages[0].(*RTCMFrame)
	if len(frame.RawBytes) != frame.TotalLen {
		t.Errorf("RawBytes length = %d, want %d (TotalLen)", len(frame.RawBytes), frame.TotalLen)
	}
	// Verify preamble
	if frame.RawBytes[0] != RTCMPreamble {
		t.Errorf("RawBytes[0] = 0x%02X, want 0xD3", frame.RawBytes[0])
	}
}

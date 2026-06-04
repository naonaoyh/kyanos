package export

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPcapNgWriter_HeaderAndBlockStructures(t *testing.T) {
	var buf bytes.Buffer
	ipToName := map[string]string{
		"192.168.1.10": "ds-pod-canary-0",
	}

	writer, err := NewPcapNgWriter(&buf, ipToName)
	if err != nil {
		t.Fatalf("NewPcapNgWriter error: %v", err)
	}

	data := buf.Bytes()
	if len(data) < 28 {
		t.Fatalf("global header size too small: %d", len(data))
	}

	// 1. Check SHB Magic Word
	shbType := binary.LittleEndian.Uint32(data[0:4])
	if shbType != blockTypeSHB {
		t.Errorf("SHB type = 0x%08X, want 0x%08X", shbType, blockTypeSHB)
	}

	shbLen := binary.LittleEndian.Uint32(data[4:8])
	if shbLen != 28 {
		t.Errorf("SHB total length = %d, want 28", shbLen)
	}

	byteOrderMagic := binary.LittleEndian.Uint32(data[8:12])
	if byteOrderMagic != 0x1A2B3C4D {
		t.Errorf("byte order magic = 0x%08X, want 0x1A2B3C4D", byteOrderMagic)
	}

	// Write packet to trigger 3-way handshake and the actual data block
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("8.8.8.8")
	payload := []byte("NTRIP-PAYLOAD")

	buf.Reset() // Clear buffer to isolate EPB blocks
	err = writer.WritePacket(time.Now(), srcIP, dstIP, 2101, 54321, payload, true, "NTRIP Request Login")
	if err != nil {
		t.Fatalf("WritePacket error: %v", err)
	}

	epbData := buf.Bytes()
	if len(epbData) == 0 {
		t.Fatalf("No EPB data written")
	}

	// We expect 4 blocks written:
	//   1. Handshake SYN (Client -> Server)
	//   2. Handshake SYN-ACK (Server -> Client)
	//   3. Handshake ACK (Client -> Server)
	//   4. Actual PSH-ACK containing "NTRIP-PAYLOAD"
	var offset int
	blockCount := 0
	for offset < len(epbData) {
		if offset+8 > len(epbData) {
			break
		}
		bType := binary.LittleEndian.Uint32(epbData[offset : offset+4])
		bLen := binary.LittleEndian.Uint32(epbData[offset+4 : offset+8])
		if bType != blockTypeEPB {
			t.Errorf("Block %d type = 0x%08X, want EPB(0x%08X)", blockCount+1, bType, blockTypeEPB)
		}
		offset += int(bLen)
		blockCount++
	}

	if blockCount != 4 {
		t.Errorf("Written block count = %d, want 4 (3 handshake + 1 payload)", blockCount)
	}
}

func TestRotateWriter_SizeTriggeredRotation(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "task-test.pcapng")

	headers := []byte{0xAA, 0xBB, 0xCC}
	rotateCount := 0

	rotator, err := NewRotateWriter(RotateWriterConfig{
		BasePath:    basePath,
		MaxSize:     20, // Small limit
		MaxDuration: 0,
		HeaderGenerator: func() []byte {
			return headers
		},
		OnRotate: func(closedPath string) {
			rotateCount++
		},
	})
	if err != nil {
		t.Fatalf("NewRotateWriter error: %v", err)
	}

	// First part has header size 3. Write 10 bytes (total 13). No rotate.
	n, err := rotator.Write([]byte("1234567890"))
	if err != nil || n != 10 {
		t.Fatalf("Write part 0: n=%d, err=%v", n, err)
	}

	// Write another 10 bytes. Total would be 23 > MaxSize(20). Trigger rotate!
	// It will close task-test.pcapng (calling OnRotate) and create task-test_part1.pcapng.
	n, err = rotator.Write([]byte("abcdefghij"))
	if err != nil || n != 10 {
		t.Fatalf("Write part 1: n=%d, err=%v", n, err)
	}

	rotator.Close()

	// Wait brief millisecond for async OnRotate call
	time.Sleep(50 * time.Millisecond)

	// We expect 2 rotations called (1 during write, 1 during Close)
	if rotateCount != 2 {
		t.Errorf("OnRotate call count = %d, want 2", rotateCount)
	}

	// Check files existence
	p0 := basePath
	p1 := filepath.Join(dir, "task-test_part1.pcapng")

	if _, err := os.Stat(p0); err != nil {
		t.Errorf("part 0 not found: %v", err)
	}
	if _, err := os.Stat(p1); err != nil {
		t.Errorf("part 1 not found: %v", err)
	}

	// Verify part 1 starts with headers
	p1Bytes, _ := os.ReadFile(p1)
	if len(p1Bytes) < 3 || p1Bytes[0] != 0xAA || p1Bytes[1] != 0xBB || p1Bytes[2] != 0xCC {
		t.Errorf("part 1 header mismatch: %v", p1Bytes)
	}
}

func TestCOSUploader_MissingCredentials(t *testing.T) {
	// Clear env vars to test error on construction
	os.Setenv("TENCENTCLOUD_SECRET_ID", "")
	os.Setenv("TENCENTCLOUD_SECRET_KEY", "")

	_, err := NewCOSUploader(COSUploaderConfig{
		Bucket: "test-123456",
		Region: "ap-beijing",
	})

	if err == nil {
		t.Errorf("expected error on missing credentials")
	}
}

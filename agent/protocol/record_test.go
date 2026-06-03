package protocol

import "testing"

// fakeMsg is a minimal ParsedMessage used to exercise Record helpers.
type fakeMsg struct {
	FrameBase
	isReq bool
}

func (m *fakeMsg) FormatToString() string { return "fake" }
func (m *fakeMsg) IsReq() bool            { return m.isReq }
func (m *fakeMsg) StreamId() StreamId     { return 0 }

func newFakeMsg(ts uint64, size int, isReq bool) *fakeMsg {
	return &fakeMsg{
		FrameBase: NewFrameBase(ts, size, 0),
		isReq:     isReq,
	}
}

// TestRecordUnidirectional verifies that a request-only record (as produced by
// the RTCM parser and by NTRIP for embedded RTCM/NMEA frames) is reported as
// unidirectional and that EffectiveResponse falls back to the request, so that
// downstream code never dereferences a nil response.
func TestRecordUnidirectional(t *testing.T) {
	req := newFakeMsg(1000, 42, true)
	r := Record{Req: req}

	if !r.IsUnidirectional() {
		t.Fatal("IsUnidirectional() = false, want true for a request-only record")
	}
	if r.Response() != nil {
		t.Fatal("Response() should be nil for a request-only record")
	}
	if got := r.EffectiveResponse(); got != ParsedMessage(req) {
		t.Fatalf("EffectiveResponse() = %v, want the request message", got)
	}
	// The exact panic site that motivated this helper.
	if ts := r.EffectiveResponse().TimestampNs(); ts != 1000 {
		t.Fatalf("EffectiveResponse().TimestampNs() = %d, want 1000", ts)
	}
	if sz := r.EffectiveResponse().ByteSize(); sz != 42 {
		t.Fatalf("EffectiveResponse().ByteSize() = %d, want 42", sz)
	}
}

// TestRecordBidirectional verifies that a normal request/response record is not
// flagged as unidirectional and that EffectiveResponse returns the response.
func TestRecordBidirectional(t *testing.T) {
	req := newFakeMsg(1000, 42, true)
	resp := newFakeMsg(2000, 84, false)
	r := Record{Req: req, Resp: resp}

	if r.IsUnidirectional() {
		t.Fatal("IsUnidirectional() = true, want false for a paired record")
	}
	if got := r.EffectiveResponse(); got != ParsedMessage(resp) {
		t.Fatalf("EffectiveResponse() = %v, want the response message", got)
	}
	if ts := r.EffectiveResponse().TimestampNs(); ts != 2000 {
		t.Fatalf("EffectiveResponse().TimestampNs() = %d, want 2000", ts)
	}
}

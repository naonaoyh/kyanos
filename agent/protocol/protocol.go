package protocol

import (
	"fmt"
	"kyanos/agent/buffer"
	"kyanos/bpf"
	"kyanos/common"
)

type ProtocolCreator func() ProtocolStreamParser

type StreamId int64

type ParsedMessageQueue []ParsedMessage

var ParsersMap map[bpf.AgentTrafficProtocolT]ProtocolCreator = make(map[bpf.AgentTrafficProtocolT]ProtocolCreator)

func GetParserByProtocol(protocol bpf.AgentTrafficProtocolT) ProtocolStreamParser {
	parserCreator, ok := ParsersMap[protocol]
	if ok {
		return parserCreator()
	}
	return nil
}

type Record struct {
	Req            ParsedMessage
	Resp           ParsedMessage
	ResponseStatus ResponseStatus
}

func NewRecord(req ParsedMessage, resp ParsedMessage) *Record {
	return &Record{
		Req:  req,
		Resp: resp,
	}
}

func (r *Record) Request() ParsedMessage {
	return r.Req
}
func (r *Record) Response() ParsedMessage {
	return r.Resp
}

// IsUnidirectional reports whether the record has no paired response message.
// This is the case for push-stream protocols such as RTCM and the RTCM/NMEA
// frames carried inside an NTRIP data stream, where each frame is modelled as
// a request with no response.
func (r *Record) IsUnidirectional() bool {
	return r.Resp == nil
}

// EffectiveResponse returns the response message, or the request message when
// the response is nil (unidirectional records). Downstream code that needs a
// timestamp or byte size for "the response side" should use this to avoid
// dereferencing a nil ParsedMessage.
func (r *Record) EffectiveResponse() ParsedMessage {
	if r.Resp != nil {
		return r.Resp
	}
	return r.Req
}

type RecordToStringOptions struct {
	RecordMaxDumpBytes int
	IncludeReqBody     bool
	IncludeRespBody    bool
}

func (r *Record) String(opt RecordToStringOptions) string {
	var result string
	if opt.IncludeReqBody {
		result += fmt.Sprintf("[ Request ]\n%s\n\n", common.TruncateString(r.Req.FormatToString(), opt.RecordMaxDumpBytes))
	}
	if opt.IncludeRespBody {
		result += fmt.Sprintf("[ Response ]\n%s\n\n", common.TruncateString(r.Resp.FormatToString(), opt.RecordMaxDumpBytes))
	}
	return result
}

type ProtocolStreamParser interface {
	ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
	FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
	Match(reqStreams map[StreamId]*ParsedMessageQueue, respStreams map[StreamId]*ParsedMessageQueue) []Record
}

type ParsedMessage interface {
	FormatToString() string
	TimestampNs() uint64
	ByteSize() int
	IsReq() bool
	Seq() uint64
	StreamId() StreamId
}

type ParseState int
type MessageType int

const (
	Request MessageType = iota
	Response
	Unknown
)

func (m MessageType) String() string {
	switch m {
	case Request:
		return "Request"
	case Response:
		return "Response"
	default:
		return "Unknwon"
	}
}

const (
	Invalid ParseState = iota
	NeedsMoreData
	Success
	Ignore
)

type ParseResult struct {
	ParseState     ParseState
	ParsedMessages []ParsedMessage
	ReadBytes      int
}

type FrameBase struct {
	timestampNs uint64
	byteSize    int
	seq         uint64
}

func NewFrameBase(timestampNs uint64, byteSize int, seq uint64) FrameBase {
	return FrameBase{timestampNs: timestampNs, byteSize: byteSize, seq: seq}
}

func (f *FrameBase) SetTimeStamp(t uint64) {
	f.timestampNs = t
}

func (f *FrameBase) TimestampNs() uint64 {
	return f.timestampNs
}

func (f *FrameBase) ByteSize() int {
	return f.byteSize
}
func (f *FrameBase) IncrByteSize(incr int) {
	f.byteSize += incr
}

func (f *FrameBase) Seq() uint64 {
	return f.seq
}

func (f *FrameBase) String() string {
	return fmt.Sprintf("timestamp_ns=%d byte_size=%d", f.timestampNs, f.byteSize)
}

type ProtocolFilter interface {
	Filter(req ParsedMessage, resp ParsedMessage) bool
	FilterByProtocol(bpf.AgentTrafficProtocolT) bool
	FilterByRequest() bool
	FilterByResponse() bool
	Protocol() bpf.AgentTrafficProtocolT
}

type StatusfulMessage interface {
	Status() ResponseStatus
}
type ResponseStatus int8

const (
	NoneStatus ResponseStatus = iota
	SuccessStatus
	FailStatus
	UnknownStatus
)

package conn

import (
	"cmp"
	"fmt"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/bpf"
	"kyanos/common"
	"slices"
	"time"
)

type RecordsProcessor struct {
	records []RecordWithConn
}

type RecordWithConn struct {
	protocol.Record
	*Connection4
}

func (p *RecordsProcessor) Run(recordChannel <-chan RecordWithConn, ticker *time.Ticker) {
	for {
		select {
		case r := <-recordChannel:
			common.AgentLog.Debugf("[RecordsProcessor] Received record: Req=%T, Resp=%T, conn=%s", r.Req, r.Resp, r.Connection4.ToString())
			if r.IsUnidirectional() {
				submitRecord(r.Record, r.Connection4)
			} else {
				p.records = append(p.records, r)
			}
		case <-ticker.C:
			if len(p.records) == 0 {
				continue
			}
			slices.SortFunc(p.records, func(r1, r2 RecordWithConn) int {
				return cmp.Compare(r1.EffectiveResponse().TimestampNs(), r2.EffectiveResponse().TimestampNs())
			})
			lastProcessIdx := -1
			now := time.Now().UnixMilli()
			for idx, record := range p.records {
				recordMills := common.NanoToMills(record.EffectiveResponse().TimestampNs())
				if float64(now)-recordMills >= 1000 {
					submitRecord(record.Record, record.Connection4)
					lastProcessIdx = idx
				}
			}
			if lastProcessIdx >= 0 {
				p.records = p.records[lastProcessIdx+1:]
			}
		}
	}
}

func bindNTRIPConnInfo(req protocol.ParsedMessage, resp protocol.ParsedMessage, c *Connection4) {
	clientIP := ""
	var clientPort uint16
	if c.Role == bpf.AgentEndpointRoleTKRoleServer {
		clientIP = c.RemoteIp.String()
		clientPort = uint16(c.RemotePort)
	} else {
		clientIP = c.LocalIp.String()
		clientPort = uint16(c.LocalPort)
	}

	connKey := fmt.Sprintf("%s:%d", clientIP, clientPort)

	if req != nil {
		if r, ok := req.(*ntrip.NTRIPRequest); ok {
			r.ClientIP = clientIP
			r.ClientPort = clientPort
			r.ConnKey = connKey
		} else if n, ok := req.(*ntrip.NTRIPNMEASentence); ok {
			n.ClientIP = clientIP
			n.ClientPort = clientPort
			n.ConnKey = connKey
		} else if rt, ok := req.(*ntrip.NTRIPRTCMFrame); ok {
			rt.ClientIP = clientIP
			rt.ClientPort = clientPort
			rt.ConnKey = connKey
		}
	}
	if resp != nil {
		if r, ok := resp.(*ntrip.NTRIPResponse); ok {
			r.ClientIP = clientIP
			r.ClientPort = clientPort
			r.ConnKey = connKey
		} else if rt, ok := resp.(*ntrip.NTRIPRTCMFrame); ok {
			rt.ClientIP = clientIP
			rt.ClientPort = clientPort
			rt.ConnKey = connKey
		}
	}
}

func submitRecord(record protocol.Record, c *Connection4) {
	var needSubmit bool

	needSubmit = c.MessageFilter.FilterByProtocol(c.Protocol)
	common.AgentLog.Debugf("[submitRecord] FilterByProtocol: %v, conn=%s", needSubmit, c.ToString())

	// Unidirectional protocols (RTCM, and RTCM/NMEA frames inside an NTRIP
	// stream) produce records with no paired response. Treat their duration as
	// zero and use the request as the effective response side for sizing.
	var duration uint64
	if record.Request() != nil {
		duration = record.EffectiveResponse().TimestampNs() - record.Request().TimestampNs()
	}
	needSubmit = needSubmit && c.LatencyFilter.Filter(float64(duration)/1000000)
	common.AgentLog.Debugf("[submitRecord] LatencyFilter: %v, duration=%d", needSubmit, duration)

	reqSize := int64(0)
	if record.Request() != nil {
		reqSize = int64(record.Request().ByteSize())
	}
	needSubmit = needSubmit &&
		c.SizeFilter.FilterByReqSize(reqSize) &&
		c.SizeFilter.FilterByRespSize(int64(record.EffectiveResponse().ByteSize()))
	common.AgentLog.Debugf("[submitRecord] SizeFilter: %v, reqSize=%d, respSize=%d", needSubmit, reqSize, record.EffectiveResponse().ByteSize())

	// Force-parse messages when export is configured, even if filters don't require it
	forceParse := RecordExportFunc != nil

	if parser := c.GetProtocolParser(c.Protocol); (needSubmit || forceParse) && parser != nil {
		var parsedRequest, parsedResponse protocol.ParsedMessage
		if (c.MessageFilter.FilterByRequest() || forceParse) && record.Request() != nil {
			parsedRequest = record.Request()
		}
		if c.MessageFilter.FilterByResponse() || forceParse {
			parsedResponse = record.Response()
		}

		// Call export hook before filtering (exports ALL parsed records)
		if RecordExportFunc != nil {
			RecordExportFunc(record)
		}

		bindNTRIPConnInfo(parsedRequest, parsedResponse, c)

		if parsedRequest != nil || parsedResponse != nil {
			needSubmit = needSubmit && c.MessageFilter.Filter(parsedRequest, parsedResponse)
		}
		common.AgentLog.Debugf("[submitRecord] MessageFilter.Filter: %v, parsedReq=%T, parsedResp=%T", needSubmit, parsedRequest, parsedResponse)
	}
	common.AgentLog.Debugf("[submitRecord] Final needSubmit: %v", needSubmit)
	if needSubmit {
		RecordFunc(record, c)
	}
}

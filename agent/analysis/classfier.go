package analysis

import (
	"fmt"

	anc "kyanos/agent/analysis/common"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"
	"kyanos/bpf"
)

type Classfier func(*anc.AnnotatedRecord) (anc.ClassId, error)
type ClassIdAsHumanReadable func(*anc.AnnotatedRecord) string

var classfierMap map[anc.ClassfierType]Classfier
var classIdHumanReadableMap map[anc.ClassfierType]ClassIdAsHumanReadable

func init() {
	classfierMap = make(map[anc.ClassfierType]Classfier)
	classfierMap[anc.None] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) { return "none", nil }
	classfierMap[anc.Conn] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(ar.ConnDesc.Identity()), nil
	}
	classfierMap[anc.RemotePort] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(fmt.Sprintf("%d", ar.RemotePort)), nil
	}
	classfierMap[anc.LocalPort] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(fmt.Sprintf("%d", ar.LocalPort)), nil
	}
	classfierMap[anc.RemoteIp] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) { return anc.ClassId(ar.RemoteAddr.String()), nil }
	classfierMap[anc.Protocol] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		return anc.ClassId(fmt.Sprintf("%d", ar.Protocol)), nil
	}
	classfierMap[anc.HttpPath] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		httpReq, ok := ar.Record.Request().(*protocol.ParsedHttpRequest)
		if !ok {
			return "_not_a_http_req_", nil
		} else {
			return anc.ClassId(httpReq.Path), nil
		}
	}
	classfierMap[anc.RedisCommand] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		redisReq, ok := ar.Record.Request().(*protocol.RedisMessage)
		if !ok {
			return "_not_a_redis_req_", nil
		} else {
			return anc.ClassId(redisReq.Command()), nil
		}
	}

	// RTCM classifiers
	classfierMap[anc.RTCMMessageType] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		// Try direct RTCM frame first
		if frame, ok := ar.Record.Request().(*rtcm.RTCMFrame); ok {
			return anc.ClassId(fmt.Sprintf("%d", frame.MessageType)), nil
		}
		// Try NTRIP-wrapped RTCM frame
		if ntripFrame, ok := ar.Record.Request().(*ntrip.NTRIPRTCMFrame); ok {
			return anc.ClassId(fmt.Sprintf("%d", ntripFrame.Inner.MessageType)), nil
		}
		return "_not_a_rtcm_frame_", nil
	}
	classfierMap[anc.RTCMConstellation] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		if frame, ok := ar.Record.Request().(*rtcm.RTCMFrame); ok {
			return anc.ClassId(frame.Constellation.String()), nil
		}
		if ntripFrame, ok := ar.Record.Request().(*ntrip.NTRIPRTCMFrame); ok {
			return anc.ClassId(ntripFrame.Inner.Constellation.String()), nil
		}
		return "_not_a_rtcm_frame_", nil
	}

	// NTRIP classifiers
	classfierMap[anc.NTRIPMountPoint] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		if req, ok := ar.Record.Request().(*ntrip.NTRIPRequest); ok {
			return anc.ClassId(req.MountPoint), nil
		}
		return "_not_a_ntrip_req_", nil
	}
	classfierMap[anc.NTRIPSessionType] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		if req, ok := ar.Record.Request().(*ntrip.NTRIPRequest); ok {
			return anc.ClassId(req.SessionType.String()), nil
		}
		return "_not_a_ntrip_req_", nil
	}

	classfierMap[anc.ProtocolAdaptive] = func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
		redisReq, ok := ar.Record.Request().(*protocol.RedisMessage)
		if !ok {
			return "_not_a_redis_req_", nil
		} else {
			return anc.ClassId(redisReq.Command()), nil
		}
	}

	classIdHumanReadableMap = make(map[anc.ClassfierType]ClassIdAsHumanReadable)
	classIdHumanReadableMap[anc.RemoteIp] = func(ar *anc.AnnotatedRecord) string {
		return ar.ConnDesc.RemoteAddr.String()
	}
	classIdHumanReadableMap[anc.RemotePort] = func(ar *anc.AnnotatedRecord) string {
		return fmt.Sprintf("%d", ar.ConnDesc.RemotePort)
	}
	classIdHumanReadableMap[anc.LocalPort] = func(ar *anc.AnnotatedRecord) string {
		return fmt.Sprintf("%d", ar.ConnDesc.LocalPort)
	}
	classIdHumanReadableMap[anc.Conn] = func(ar *anc.AnnotatedRecord) string {
		return ar.ConnDesc.SimpleString()
	}
	classIdHumanReadableMap[anc.HttpPath] = func(ar *anc.AnnotatedRecord) string {
		httpReq, ok := ar.Record.Request().(*protocol.ParsedHttpRequest)
		if !ok {
			return "_not_a_http_req_"
		} else {
			return httpReq.Path
		}
	}
	classIdHumanReadableMap[anc.RedisCommand] = func(ar *anc.AnnotatedRecord) string {
		redisReq, ok := ar.Record.Request().(*protocol.RedisMessage)
		if !ok {
			return "_not_a_redis_req_"
		} else {
			return redisReq.Command()
		}
	}

	// RTCM human-readable classifiers
	classIdHumanReadableMap[anc.RTCMMessageType] = func(ar *anc.AnnotatedRecord) string {
		if frame, ok := ar.Record.Request().(*rtcm.RTCMFrame); ok {
			return fmt.Sprintf("%d (%s)", frame.MessageType, rtcm.GetMessageName(frame.MessageType))
		}
		if ntripFrame, ok := ar.Record.Request().(*ntrip.NTRIPRTCMFrame); ok {
			return fmt.Sprintf("%d (%s)", ntripFrame.Inner.MessageType, rtcm.GetMessageName(ntripFrame.Inner.MessageType))
		}
		return "_not_a_rtcm_frame_"
	}
	classIdHumanReadableMap[anc.RTCMConstellation] = func(ar *anc.AnnotatedRecord) string {
		if frame, ok := ar.Record.Request().(*rtcm.RTCMFrame); ok {
			return frame.Constellation.String()
		}
		if ntripFrame, ok := ar.Record.Request().(*ntrip.NTRIPRTCMFrame); ok {
			return ntripFrame.Inner.Constellation.String()
		}
		return "_not_a_rtcm_frame_"
	}

	// NTRIP human-readable classifiers
	classIdHumanReadableMap[anc.NTRIPMountPoint] = func(ar *anc.AnnotatedRecord) string {
		if req, ok := ar.Record.Request().(*ntrip.NTRIPRequest); ok {
			return req.MountPoint
		}
		return "_not_a_ntrip_req_"
	}
	classIdHumanReadableMap[anc.NTRIPSessionType] = func(ar *anc.AnnotatedRecord) string {
		if req, ok := ar.Record.Request().(*ntrip.NTRIPRequest); ok {
			return req.SessionType.String()
		}
		return "_not_a_ntrip_req_"
	}

	classIdHumanReadableMap[anc.Protocol] = func(ar *anc.AnnotatedRecord) string {
		return bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(ar.Protocol)]
	}
}

func getClassfier(classfierType anc.ClassfierType, options anc.AnalysisOptions) Classfier {
	if classfierType == anc.ProtocolAdaptive {
		return func(ar *anc.AnnotatedRecord) (anc.ClassId, error) {
			c, ok := options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolT(ar.Protocol)]
			if !ok {
				return classfierMap[anc.RemoteIp](ar)
			} else {
				return classfierMap[c](ar)
			}
		}
	} else {
		return classfierMap[classfierType]
	}
}

func GetClassfierType(classfierType anc.ClassfierType, options anc.AnalysisOptions, r *anc.AnnotatedRecord) anc.ClassfierType {
	if classfierType == anc.ProtocolAdaptive {
		c, ok := options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolT(r.Protocol)]
		if ok {
			return c
		} else {
			return anc.RemoteIp
		}
	} else {
		return classfierType
	}
}

func getClassIdHumanReadableFunc(classfierType anc.ClassfierType, options anc.AnalysisOptions) (ClassIdAsHumanReadable, bool) {
	if classfierType == anc.ProtocolAdaptive {
		return func(ar *anc.AnnotatedRecord) string {
			c, ok := options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolT(ar.Protocol)]
			if !ok {
				return classIdHumanReadableMap[anc.RemoteIp](ar)
			} else {
				return classIdHumanReadableMap[c](ar)
			}
		}, true
	} else {
		f, ok := classIdHumanReadableMap[classfierType]
		return f, ok
	}
}

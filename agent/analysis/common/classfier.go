package common

var ClassfierTypeNames = map[ClassfierType]string{
	None:              "none",
	Conn:              "conn",
	RemotePort:        "remote-port",
	LocalPort:         "local-port",
	RemoteIp:          "remote-ip",
	Protocol:          "protocol",
	HttpPath:          "http-path",
	RedisCommand:      "redis-command",
	RTCMMessageType:   "rtcm-msg-type",
	RTCMConstellation: "rtcm-constellation",
	NTRIPMountPoint:   "ntrip-mount",
	NTRIPSessionType:  "ntrip-session",
	ProtocolAdaptive:  "protocol-adaptive",
	Default:           "default",
}

const (
	Default ClassfierType = iota
	None
	Conn
	RemotePort
	LocalPort
	RemoteIp
	Protocol

	// Http
	HttpPath

	// Redis
	RedisCommand

	// RTCM 3.x GNSS correction data
	RTCMMessageType   // Group by RTCM message type (e.g., 1074, 1077, 1005)
	RTCMConstellation // Group by GNSS constellation (GPS, GLONASS, Galileo, etc.)

	// NTRIP v1/v2 protocol
	NTRIPMountPoint  // Group by NTRIP mountpoint name
	NTRIPSessionType // Group by NTRIP session type (DataStream, SourcePush, Sourcetable)

	ProtocolAdaptive
)

type ClassId string

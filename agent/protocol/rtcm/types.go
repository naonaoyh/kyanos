package rtcm

// RTCM 3.x message type constants.
// Reference: RTCM 10400.3 standard

// RTCM frame structure constants
const (
	RTCMPreamble     byte = 0xD3
	RTCMMinFrameLen  int  = 6    // preamble(1) + header(2) + CRC(3) minimum, 0 payload
	RTCMMaxPayload   int  = 1023 // 10-bit length field maximum
	RTCMHeaderLen    int  = 3    // preamble(1) + reserved+length(2)
	RTCMCRCLen       int  = 3    // CRC-24Q is 3 bytes
	MaxMessageNumber int  = 4095 // 12-bit message number maximum
)

// Common RTCM 3.x message types
const (
	// Station metadata
	Msg1005 = 1005 // Stationary RTK Reference Station ARP
	Msg1006 = 1006 // Stationary RTK Reference Station ARP with Antenna Height
	Msg1007 = 1007 // Antenna Descriptor
	Msg1008 = 1008 // Antenna Descriptor with Serial Number
	Msg1033 = 1033 // Receiver and Antenna Descriptor

	// GPS observations (legacy)
	Msg1001 = 1001 // GPS L1-Only RTK Observables
	Msg1002 = 1002 // GPS Extended L1-Only RTK Observables
	Msg1003 = 1003 // GPS L1&L2 RTK Observables
	Msg1004 = 1004 // GPS Extended L1&L2 RTK Observables

	// GLONASS observations (legacy)
	Msg1009 = 1009 // GLONASS L1-Only RTK Observables
	Msg1010 = 1010 // GLONASS Extended L1-Only RTK Observables
	Msg1011 = 1011 // GLONASS L1&L2 RTK Observables
	Msg1012 = 1012 // GLONASS Extended L1&L2 RTK Observables

	// Auxiliary messages
	Msg1013 = 1013 // System Parameters
	Msg1029 = 1029 // Unicode Text String
	Msg1030 = 1030 // GPS Network RTK Residual
	Msg1031 = 1031 // GLONASS Network RTK Residual
	Msg1032 = 1032 // Physical Reference Station Position

	// GPS ephemeris
	Msg1019 = 1019 // GPS Ephemeris

	// GLONASS ephemeris
	Msg1020 = 1020 // GLONASS Ephemeris

	// GPS MSM (Multiple Signal Messages)
	Msg1071 = 1071 // GPS MSM1
	Msg1072 = 1072 // GPS MSM2
	Msg1073 = 1073 // GPS MSM3
	Msg1074 = 1074 // GPS MSM4 (full pseudorange + carrier phase)
	Msg1075 = 1075 // GPS MSM5
	Msg1076 = 1076 // GPS MSM6
	Msg1077 = 1077 // GPS MSM7 (full observables with CNR)

	// GLONASS MSM
	Msg1081 = 1081 // GLONASS MSM1
	Msg1082 = 1082 // GLONASS MSM2
	Msg1083 = 1083 // GLONASS MSM3
	Msg1084 = 1084 // GLONASS MSM4
	Msg1085 = 1085 // GLONASS MSM5
	Msg1086 = 1086 // GLONASS MSM6
	Msg1087 = 1087 // GLONASS MSM7

	// Galileo MSM
	Msg1091 = 1091 // Galileo MSM1
	Msg1092 = 1092 // Galileo MSM2
	Msg1093 = 1093 // Galileo MSM3
	Msg1094 = 1094 // Galileo MSM4
	Msg1095 = 1095 // Galileo MSM5
	Msg1096 = 1096 // Galileo MSM6
	Msg1097 = 1097 // Galileo MSM7

	// SBAS MSM
	Msg1101 = 1101 // SBAS MSM1
	Msg1102 = 1102 // SBAS MSM2
	Msg1103 = 1103 // SBAS MSM3
	Msg1104 = 1104 // SBAS MSM4
	Msg1105 = 1105 // SBAS MSM5
	Msg1106 = 1106 // SBAS MSM6
	Msg1107 = 1107 // SBAS MSM7

	// QZSS MSM
	Msg1111 = 1111 // QZSS MSM1
	Msg1112 = 1112 // QZSS MSM2
	Msg1113 = 1113 // QZSS MSM3
	Msg1114 = 1114 // QZSS MSM4
	Msg1115 = 1115 // QZSS MSM5
	Msg1116 = 1116 // QZSS MSM6
	Msg1117 = 1117 // QZSS MSM7

	// BeiDou MSM
	Msg1121 = 1121 // BeiDou MSM1
	Msg1122 = 1122 // BeiDou MSM2
	Msg1123 = 1123 // BeiDou MSM3
	Msg1124 = 1124 // BeiDou MSM4
	Msg1125 = 1125 // BeiDou MSM5
	Msg1126 = 1126 // BeiDou MSM6
	Msg1127 = 1127 // BeiDou MSM7

	// NavIC MSM
	Msg1131 = 1131 // NavIC MSM1
	Msg1132 = 1132 // NavIC MSM2
	Msg1133 = 1133 // NavIC MSM3
	Msg1134 = 1134 // NavIC MSM4
	Msg1135 = 1135 // NavIC MSM5
	Msg1136 = 1136 // NavIC MSM6
	Msg1137 = 1137 // NavIC MSM7

	// GLONASS code-phase biases
	Msg1230 = 1230 // GLONASS Code-Phase Biases

	// QZSS ephemeris
	Msg1044 = 1044 // QZSS Ephemeris

	// Galileo ephemeris
	Msg1045 = 1045 // Galileo F/NAV Satellite Ephemeris
	Msg1046 = 1046 // Galileo I/NAV Satellite Ephemeris

	// BeiDou ephemeris
	Msg1042 = 1042 // BeiDou Ephemeris
)

// MessageTypeNames maps RTCM message type numbers to human-readable names.
var MessageTypeNames = map[int]string{
	1001: "GPS L1 RTK Obs",
	1002: "GPS Ext L1 RTK Obs",
	1003: "GPS L1&L2 RTK Obs",
	1004: "GPS Ext L1&L2 RTK Obs",
	1005: "Station ARP Coords",
	1006: "Station ARP w/ Height",
	1007: "Antenna Descriptor",
	1008: "Antenna Desc w/ Serial",
	1009: "GLONASS L1 RTK Obs",
	1010: "GLONASS Ext L1 RTK Obs",
	1011: "GLONASS L1&L2 RTK Obs",
	1012: "GLONASS Ext L1&L2 RTK Obs",
	1013: "System Parameters",
	1019: "GPS Ephemeris",
	1020: "GLONASS Ephemeris",
	1029: "Unicode Text",
	1030: "GPS Net RTK Residual",
	1031: "GLONASS Net RTK Residual",
	1032: "Physical Ref Station Pos",
	1033: "Receiver & Antenna Desc",
	1042: "BeiDou Ephemeris",
	1044: "QZSS Ephemeris",
	1045: "Galileo F/NAV Eph",
	1046: "Galileo I/NAV Eph",
	1071: "GPS MSM1",
	1072: "GPS MSM2",
	1073: "GPS MSM3",
	1074: "GPS MSM4",
	1075: "GPS MSM5",
	1076: "GPS MSM6",
	1077: "GPS MSM7",
	1081: "GLO MSM1",
	1082: "GLO MSM2",
	1083: "GLO MSM3",
	1084: "GLO MSM4",
	1085: "GLO MSM5",
	1086: "GLO MSM6",
	1087: "GLO MSM7",
	1091: "GAL MSM1",
	1092: "GAL MSM2",
	1093: "GAL MSM3",
	1094: "GAL MSM4",
	1095: "GAL MSM5",
	1096: "GAL MSM6",
	1097: "GAL MSM7",
	1101: "SBAS MSM1",
	1102: "SBAS MSM2",
	1103: "SBAS MSM3",
	1104: "SBAS MSM4",
	1105: "SBAS MSM5",
	1106: "SBAS MSM6",
	1107: "SBAS MSM7",
	1111: "QZSS MSM1",
	1112: "QZSS MSM2",
	1113: "QZSS MSM3",
	1114: "QZSS MSM4",
	1115: "QZSS MSM5",
	1116: "QZSS MSM6",
	1117: "QZSS MSM7",
	1121: "BDS MSM1",
	1122: "BDS MSM2",
	1123: "BDS MSM3",
	1124: "BDS MSM4",
	1125: "BDS MSM5",
	1126: "BDS MSM6",
	1127: "BDS MSM7",
	1131: "NavIC MSM1",
	1132: "NavIC MSM2",
	1133: "NavIC MSM3",
	1134: "NavIC MSM4",
	1135: "NavIC MSM5",
	1136: "NavIC MSM6",
	1137: "NavIC MSM7",
	1230: "GLO Code-Phase Bias",
}

// Constellation represents a GNSS constellation type.
type Constellation int

const (
	ConstellationUnknown Constellation = iota
	ConstellationGPS
	ConstellationGLONASS
	ConstellationGalileo
	ConstellationSBAS
	ConstellationQZSS
	ConstellationBeiDou
	ConstellationNavIC
)

func (c Constellation) String() string {
	switch c {
	case ConstellationGPS:
		return "GPS"
	case ConstellationGLONASS:
		return "GLONASS"
	case ConstellationGalileo:
		return "Galileo"
	case ConstellationSBAS:
		return "SBAS"
	case ConstellationQZSS:
		return "QZSS"
	case ConstellationBeiDou:
		return "BeiDou"
	case ConstellationNavIC:
		return "NavIC"
	default:
		return "Unknown"
	}
}

// InferConstellation determines the GNSS constellation from the RTCM message type.
func InferConstellation(msgType int) Constellation {
	switch {
	// GPS: legacy 1001-1004, ephemeris 1019, MSM 1071-1077
	case msgType >= 1001 && msgType <= 1004:
		return ConstellationGPS
	case msgType == 1019:
		return ConstellationGPS
	case msgType >= 1071 && msgType <= 1077:
		return ConstellationGPS
	// GLONASS: legacy 1009-1012, ephemeris 1020, MSM 1081-1087, bias 1230
	case msgType >= 1009 && msgType <= 1012:
		return ConstellationGLONASS
	case msgType == 1020:
		return ConstellationGLONASS
	case msgType >= 1081 && msgType <= 1087:
		return ConstellationGLONASS
	case msgType == 1230:
		return ConstellationGLONASS
	// Galileo: ephemeris 1045/1046, MSM 1091-1097
	case msgType == 1045 || msgType == 1046:
		return ConstellationGalileo
	case msgType >= 1091 && msgType <= 1097:
		return ConstellationGalileo
	// SBAS: MSM 1101-1107
	case msgType >= 1101 && msgType <= 1107:
		return ConstellationSBAS
	// QZSS: ephemeris 1044, MSM 1111-1117
	case msgType == 1044:
		return ConstellationQZSS
	case msgType >= 1111 && msgType <= 1117:
		return ConstellationQZSS
	// BeiDou: ephemeris 1042, MSM 1121-1127
	case msgType == 1042:
		return ConstellationBeiDou
	case msgType >= 1121 && msgType <= 1127:
		return ConstellationBeiDou
	// NavIC: MSM 1131-1137
	case msgType >= 1131 && msgType <= 1137:
		return ConstellationNavIC
	default:
		return ConstellationUnknown
	}
}

// MSMClass represents the MSM (Multiple Signal Message) class.
type MSMClass int

const (
	MSMUnknown MSMClass = iota
	MSM1                // Coarse pseudorange
	MSM2                // Fine pseudorange
	MSM3                // Coarse pseudorange + fine carrier phase
	MSM4                // Full pseudorange + carrier phase
	MSM5                // Full + CNR
	MSM6                // Full high-resolution
	MSM7                // Full high-resolution + CNR
)

func (m MSMClass) String() string {
	switch m {
	case MSM1:
		return "MSM1"
	case MSM2:
		return "MSM2"
	case MSM3:
		return "MSM3"
	case MSM4:
		return "MSM4"
	case MSM5:
		return "MSM5"
	case MSM6:
		return "MSM6"
	case MSM7:
		return "MSM7"
	default:
		return ""
	}
}

// MSMDescription returns a human-readable description of what data each MSM class carries.
func MSMDescription(m MSMClass) string {
	switch m {
	case MSM1:
		return "Coarse pseudorange"
	case MSM2:
		return "Fine pseudorange"
	case MSM3:
		return "Coarse pseudorange + fine carrier phase"
	case MSM4:
		return "Full pseudorange + carrier phase"
	case MSM5:
		return "Full + CNR + Doppler"
	case MSM6:
		return "Full high-resolution"
	case MSM7:
		return "Full high-resolution + CNR + Doppler"
	default:
		return ""
	}
}

// InferMSMClass determines the MSM class from the RTCM message type.
// Returns MSMUnknown if the message is not an MSM type.
func InferMSMClass(msgType int) MSMClass {
	// MSM messages have the pattern: constellation_base + (class - 1)
	// GPS: 1071-1077 (MSM1-MSM7)
	// GLONASS: 1081-1087
	// Galileo: 1091-1097
	// SBAS: 1101-1107
	// QZSS: 1111-1117
	// BeiDou: 1121-1127
	// NavIC: 1131-1137
	msmBases := []int{1071, 1081, 1091, 1101, 1111, 1121, 1131}
	for _, base := range msmBases {
		if msgType >= base && msgType <= base+6 {
			return MSMClass(msgType - base + 1)
		}
	}
	return MSMUnknown
}

// IsMSMMessage returns true if the message type is an MSM message.
func IsMSMMessage(msgType int) bool {
	return InferMSMClass(msgType) != MSMUnknown
}

// GetMessageName returns the human-readable name for an RTCM message type.
// Returns a formatted string like "RTCM 1234" if the type is not in the known map.
func GetMessageName(msgType int) string {
	if name, ok := MessageTypeNames[msgType]; ok {
		return name
	}
	return "Unknown"
}

package ntrip

import (
	"fmt"
	"strconv"
	"strings"
)

// Sourcetable represents a parsed NTRIP SOURCETABLE response.
type Sourcetable struct {
	Casters  []CasterEntry
	Networks []NetworkEntry
	Mounts   []StreamEntry
	RawText  string // Original sourcetable text
}

// CasterEntry represents a CAS line in the sourcetable.
type CasterEntry struct {
	Host       string
	Port       int
	Identifier string
	Operator   string
	NMEA       bool
	Country    string
	Latitude   float64
	Longitude  float64
	Misc       string
}

// NetworkEntry represents a NET line in the sourcetable.
type NetworkEntry struct {
	Identifier     string
	Operator       string
	Authentication string
	Fee            string
	WebURL         string
	Misc           string
}

// StreamEntry represents a STR line in the sourcetable.
// This is the most important entry type, describing available mountpoints.
type StreamEntry struct {
	MountPoint     string
	Identifier     string
	Format         string
	FormatDetails  string
	Carrier        string
	NavSystem      string
	Network        string
	Country        string
	Latitude       float64
	Longitude      float64
	NMEA           bool
	Solution       string
	Generator      string
	Compression    string
	Authentication string
	Fee            string
	Bitrate        int
	Misc           string
}

// ParseSourcetable parses the raw text of an NTRIP SOURCETABLE response.
func ParseSourcetable(rawText string) *Sourcetable {
	st := &Sourcetable{
		RawText: rawText,
	}

	lines := strings.Split(rawText, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" || line == "ENDSOURCETABLE" {
			continue
		}

		parts := strings.Split(line, ";")
		if len(parts) < 2 {
			continue
		}

		switch parts[0] {
		case "CAS":
			if entry := parseCasterEntry(parts); entry != nil {
				st.Casters = append(st.Casters, *entry)
			}
		case "NET":
			if entry := parseNetworkEntry(parts); entry != nil {
				st.Networks = append(st.Networks, *entry)
			}
		case "STR":
			if entry := parseStreamEntry(parts); entry != nil {
				st.Mounts = append(st.Mounts, *entry)
			}
		}
	}

	return st
}

// parseCasterEntry parses a CAS line.
// Format: CAS;host;port;identifier;operator;NMEA;country;lat;lon;fallback_host;fallback_port;misc
func parseCasterEntry(parts []string) *CasterEntry {
	if len(parts) < 10 {
		return nil
	}

	port, _ := strconv.Atoi(parts[2])
	lat, _ := strconv.ParseFloat(parts[7], 64)
	lon, _ := strconv.ParseFloat(parts[8], 64)

	return &CasterEntry{
		Host:       parts[1],
		Port:       port,
		Identifier: parts[3],
		Operator:   parts[4],
		NMEA:       parts[5] == "1",
		Country:    parts[6],
		Latitude:   lat,
		Longitude:  lon,
		Misc:       safeGet(parts, 11),
	}
}

// parseNetworkEntry parses a NET line.
// Format: NET;identifier;operator;authentication;fee;web-url;address;misc
func parseNetworkEntry(parts []string) *NetworkEntry {
	if len(parts) < 7 {
		return nil
	}

	return &NetworkEntry{
		Identifier:     parts[1],
		Operator:       parts[2],
		Authentication: parts[3],
		Fee:            parts[4],
		WebURL:         parts[5],
		Misc:           safeGet(parts, 7),
	}
}

// parseStreamEntry parses a STR line.
// Format: STR;mountpoint;identifier;format;format-details;carrier;nav-system;network;
//
//	country;lat;lon;nmea;solution;generator;compression;authentication;fee;bitrate;misc
func parseStreamEntry(parts []string) *StreamEntry {
	if len(parts) < 19 {
		// Minimum required fields
		if len(parts) < 2 {
			return nil
		}
	}

	lat, _ := strconv.ParseFloat(safeGet(parts, 9), 64)
	lon, _ := strconv.ParseFloat(safeGet(parts, 10), 64)
	bitrate, _ := strconv.Atoi(safeGet(parts, 17))

	return &StreamEntry{
		MountPoint:     safeGet(parts, 1),
		Identifier:     safeGet(parts, 2),
		Format:         safeGet(parts, 3),
		FormatDetails:  safeGet(parts, 4),
		Carrier:        safeGet(parts, 5),
		NavSystem:      safeGet(parts, 6),
		Network:        safeGet(parts, 7),
		Country:        safeGet(parts, 8),
		Latitude:       lat,
		Longitude:      lon,
		NMEA:           safeGet(parts, 11) == "1",
		Solution:       safeGet(parts, 12),
		Generator:      safeGet(parts, 13),
		Compression:    safeGet(parts, 14),
		Authentication: safeGet(parts, 15),
		Fee:            safeGet(parts, 16),
		Bitrate:        bitrate,
		Misc:           safeGet(parts, 18),
	}
}

// FormatToString returns a human-readable representation of the sourcetable.
func (st *Sourcetable) FormatToString() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Sourcetable: %d casters, %d networks, %d mountpoints\n",
		len(st.Casters), len(st.Networks), len(st.Mounts)))

	if len(st.Mounts) > 0 {
		sb.WriteString("Mountpoints:\n")
		for _, m := range st.Mounts {
			sb.WriteString(fmt.Sprintf("  %s: %s (%s) @ [%.4f, %.4f]\n",
				m.MountPoint, m.Identifier, m.Format, m.Latitude, m.Longitude))
		}
	}

	return sb.String()
}

// GetMountPointNames returns a list of all mountpoint names in the sourcetable.
func (st *Sourcetable) GetMountPointNames() []string {
	names := make([]string, 0, len(st.Mounts))
	for _, m := range st.Mounts {
		names = append(names, m.MountPoint)
	}
	return names
}

// safeGet safely gets a string from a slice, returning "" if out of bounds.
func safeGet(parts []string, idx int) string {
	if idx < len(parts) {
		return parts[idx]
	}
	return ""
}

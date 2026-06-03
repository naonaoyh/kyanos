package cmd

import (
	"kyanos/agent/protocol/ntrip"
	"strings"

	"github.com/spf13/cobra"
)

var ntripCmd *cobra.Command = &cobra.Command{
	Use:   "ntrip [--mount MOUNTPOINTS] [--version v1|v2] [--method GET|POST|SOURCE] [--session TYPE] [--user USERNAMES] [--gga] [--errors] [--export FILE]",
	Short: "Watch NTRIP v1/v2 protocol sessions for GNSS correction data streaming",
	Long: `Monitor NTRIP (Networked Transport of RTCM via Internet Protocol) sessions.
NTRIP is the standard protocol for streaming GNSS correction data over HTTP,
supporting both v1 (ICY/SOURCETABLE) and v2 (standard HTTP/1.1) variants.

Examples:
  # Watch all NTRIP traffic
  sudo kyanos watch ntrip

  # Filter by specific mountpoints
  sudo kyanos watch ntrip --mount MOUNT01,MOUNT02

  # Show only NTRIP v2 sessions
  sudo kyanos watch ntrip --version v2

  # Filter by session type (data, source, sourcetable)
  sudo kyanos watch ntrip --session data

  # Filter by username (auth credentials)
  sudo kyanos watch ntrip --user admin,operator

  # Show only client GGA position uploads
  sudo kyanos watch ntrip --gga

  # Show only error responses
  sudo kyanos watch ntrip --errors

  # Export RTCM data from NTRIP stream to file
  sudo kyanos watch ntrip --export output.rtcm

  # Combine filters
  sudo kyanos watch ntrip --mount MOUNT01 --version v2 --user admin`,
	Run: func(cmd *cobra.Command, args []string) {
		mounts, err := cmd.Flags().GetStringSlice("mount")
		if err != nil {
			logger.Fatalf("invalid mount: %v\n", err)
		}

		versionStrs, err := cmd.Flags().GetStringSlice("version")
		if err != nil {
			logger.Fatalf("invalid version: %v\n", err)
		}

		methodStrs, err := cmd.Flags().GetStringSlice("method")
		if err != nil {
			logger.Fatalf("invalid method: %v\n", err)
		}

		sessionStrs, err := cmd.Flags().GetStringSlice("session")
		if err != nil {
			logger.Fatalf("invalid session: %v\n", err)
		}

		users, err := cmd.Flags().GetStringSlice("user")
		if err != nil {
			logger.Fatalf("invalid user: %v\n", err)
		}

		errorsOnly, err := cmd.Flags().GetBool("errors")
		if err != nil {
			logger.Fatalf("invalid errors: %v\n", err)
		}

		crcErrors, err := cmd.Flags().GetBool("crc-errors")
		if err != nil {
			logger.Fatalf("invalid crc-errors: %v\n", err)
		}

		ggaOnly, err := cmd.Flags().GetBool("gga")
		if err != nil {
			logger.Fatalf("invalid gga: %v\n", err)
		}

		exportPath, err := cmd.Flags().GetString("export")
		if err != nil {
			logger.Fatalf("invalid export: %v\n", err)
		}

		// Parse version strings
		versions := parseNTRIPVersions(versionStrs)

		// Parse session type strings
		sessionTypes := parseNTRIPSessionTypes(sessionStrs)

		// Normalize methods to uppercase
		methods := make([]string, 0, len(methodStrs))
		for _, m := range methodStrs {
			methods = append(methods, strings.ToUpper(strings.TrimSpace(m)))
		}

		options.MessageFilter = ntrip.NTRIPFilter{
			TargetVersions:     versions,
			TargetSessionTypes: sessionTypes,
			TargetMountPoints:  mounts,
			TargetMethods:      methods,
			TargetUsernames:    users,
			ErrorsOnly:         errorsOnly,
			CRCErrorsOnly:      crcErrors,
			GGAOnly:            ggaOnly,
		}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)

		// Set up RTCM export if --export is specified
		if exportPath != "" {
			setupRTCMExport(exportPath)
		}

		// Enable session diagnostics if --diag is specified
		initSessionDiagnosis(cmd)
		applyLeapSeconds(cmd)

		startAgent()
	},
}

// parseNTRIPVersions converts version strings ("v1", "v2") to NTRIPVersion enum values.
func parseNTRIPVersions(strs []string) []ntrip.NTRIPVersion {
	result := make([]ntrip.NTRIPVersion, 0, len(strs))
	for _, s := range strs {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "v1", "1", "ntripv1":
			result = append(result, ntrip.NTRIPv1)
		case "v2", "2", "ntripv2":
			result = append(result, ntrip.NTRIPv2)
		}
	}
	return result
}

// parseNTRIPSessionTypes converts session type strings to NTRIPSessionType enum values.
func parseNTRIPSessionTypes(strs []string) []ntrip.NTRIPSessionType {
	result := make([]ntrip.NTRIPSessionType, 0, len(strs))
	for _, s := range strs {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "data", "datastream", "stream":
			result = append(result, ntrip.SessionTypeDataStream)
		case "source", "sourcepush", "push":
			result = append(result, ntrip.SessionTypeSourcePush)
		case "sourcetable", "table", "list":
			result = append(result, ntrip.SessionTypeSourcetable)
		}
	}
	return result
}

func init() {
	ntripCmd.Flags().StringSlice("mount", []string{},
		"Filter by mountpoint names (e.g. MOUNT01,MOUNT02)")
	ntripCmd.Flags().StringSlice("version", []string{},
		"Filter by NTRIP version: v1,v2")
	ntripCmd.Flags().StringSlice("method", []string{},
		"Filter by HTTP method: GET,POST,SOURCE")
	ntripCmd.Flags().StringSlice("session", []string{},
		"Filter by session type: data,source,sourcetable")
	ntripCmd.Flags().StringSlice("user", []string{},
		"Filter by username in auth credentials (e.g. admin,operator)")
	ntripCmd.Flags().Bool("errors", false,
		"Only show error responses (status >= 400 or ERROR prefix)")
	ntripCmd.Flags().Bool("crc-errors", false,
		"Only show RTCM frames with CRC-24Q validation errors")
	ntripCmd.Flags().Bool("gga", false,
		"Only show client GGA position uploads (NMEA backchannel)")
	ntripCmd.Flags().String("export", "",
		"Export RTCM frames from NTRIP stream to a .rtcm binary file")
	addSessionDiagnosisFlags(ntripCmd)
	ntripCmd.Flags().SortFlags = false
	ntripCmd.PersistentFlags().SortFlags = false

	copy := *ntripCmd
	watchCmd.AddCommand(&copy)
	copy2 := *ntripCmd
	statCmd.AddCommand(&copy2)
}

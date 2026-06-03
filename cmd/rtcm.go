package cmd

import (
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/ntrip"
	"kyanos/agent/protocol/rtcm"

	"github.com/spf13/cobra"
)

var rtcmCmd *cobra.Command = &cobra.Command{
	Use:   "rtcm [--msg-type TYPES] [--constellation CONSTELLATIONS] [--crc-errors] [--export FILE]",
	Short: "Watch RTCM 3.x GNSS correction data frames",
	Long: `Monitor RTCM 3.x frames from GNSS correction data streams.
RTCM (Radio Technical Commission for Maritime Services) 3.x is the standard
binary format for GNSS correction data, commonly transmitted via NTRIP or TCP.

Examples:
  # Watch all RTCM frames
  sudo kyanos watch rtcm

  # Filter by specific message types
  sudo kyanos watch rtcm --msg-type 1074,1124,1005

  # Filter by constellation (GPS, GLONASS, Galileo, BeiDou, QZSS, SBAS, NavIC)
  sudo kyanos watch rtcm --constellation GPS,BeiDou

  # Show only frames with CRC validation errors
  sudo kyanos watch rtcm --crc-errors

  # Export all RTCM frames to a .rtcm file (usable by RTKLIB, rtkrcv, convbin)
  sudo kyanos watch rtcm --export output.rtcm

  # Combine filters
  sudo kyanos watch rtcm --constellation GPS --msg-type 1077 --latency 10`,
	Run: func(cmd *cobra.Command, args []string) {
		msgTypes, err := cmd.Flags().GetIntSlice("msg-type")
		if err != nil {
			logger.Fatalf("invalid msg-type: %v\n", err)
		}

		constellationStrs, err := cmd.Flags().GetStringSlice("constellation")
		if err != nil {
			logger.Fatalf("invalid constellation: %v\n", err)
		}

		crcErrors, err := cmd.Flags().GetBool("crc-errors")
		if err != nil {
			logger.Fatalf("invalid crc-errors: %v\n", err)
		}

		exportPath, err := cmd.Flags().GetString("export")
		if err != nil {
			logger.Fatalf("invalid export: %v\n", err)
		}

		// Parse constellation strings to Constellation type
		constellations := parseConstellations(constellationStrs)

		options.MessageFilter = rtcm.RTCMFilter{
			TargetMessageTypes:   msgTypes,
			TargetConstellations: constellations,
			CRCErrorsOnly:        crcErrors,
		}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)

		// Set up RTCM export if --export is specified
		if exportPath != "" {
			setupRTCMExport(exportPath)
		}

		startAgent()
	},
}

// setupRTCMExport creates an RTCMExporter and wires it into the agent pipeline.
func setupRTCMExport(path string) {
	exporter, err := rtcm.NewRTCMExporter(path)
	if err != nil {
		logger.Fatalf("failed to create RTCM exporter: %v\n", err)
	}
	logger.Printf("RTCM export enabled: writing frames to %s\n", path)

	conn.RecordExportFunc = func(record protocol.Record) {
		// Handle direct RTCM frames
		if frame, ok := record.Request().(*rtcm.RTCMFrame); ok && frame.CRCValid {
			if err := exporter.WriteFrame(frame); err != nil {
				logger.Printf("RTCM export write error: %v\n", err)
			}
			return
		}
		// Handle NTRIP-wrapped RTCM frames
		if ntripFrame, ok := record.Request().(*ntrip.NTRIPRTCMFrame); ok && ntripFrame.Inner.CRCValid {
			if err := exporter.WriteFrame(ntripFrame.Inner); err != nil {
				logger.Printf("RTCM export write error: %v\n", err)
			}
			return
		}
	}

	// Register cleanup on signal
	origStopper := options.Stopper
	if origStopper == nil {
		return
	}
	go func() {
		sig := <-origStopper
		exporter.Close()
		logger.Printf("RTCM export closed: %s\n", path)
		// Re-send signal for normal shutdown
		origStopper <- sig
	}()
}

// parseConstellations converts constellation name strings to Constellation type slice.
func parseConstellations(strs []string) []rtcm.Constellation {
	result := make([]rtcm.Constellation, 0, len(strs))
	for _, s := range strs {
		switch s {
		case "GPS", "gps":
			result = append(result, rtcm.ConstellationGPS)
		case "GLONASS", "glonass", "GLO", "glo":
			result = append(result, rtcm.ConstellationGLONASS)
		case "Galileo", "galileo", "GAL", "gal":
			result = append(result, rtcm.ConstellationGalileo)
		case "BeiDou", "beidou", "BDS", "bds":
			result = append(result, rtcm.ConstellationBeiDou)
		case "QZSS", "qzss":
			result = append(result, rtcm.ConstellationQZSS)
		case "SBAS", "sbas":
			result = append(result, rtcm.ConstellationSBAS)
		case "NavIC", "navic", "IRNSS", "irnss":
			result = append(result, rtcm.ConstellationNavIC)
		}
	}
	return result
}

func init() {
	rtcmCmd.Flags().IntSlice("msg-type", []int{},
		"Filter by RTCM message types (e.g. 1005,1074,1127)")
	rtcmCmd.Flags().StringSlice("constellation", []string{},
		"Filter by GNSS constellation: GPS,GLONASS,Galileo,BeiDou,QZSS,SBAS,NavIC")
	rtcmCmd.Flags().Bool("crc-errors", false,
		"Only show frames with CRC-24Q validation errors")
	rtcmCmd.Flags().String("export", "",
		"Export all valid RTCM frames to a .rtcm binary file (for RTKLIB, rtkrcv, convbin)")
	rtcmCmd.Flags().SortFlags = false
	rtcmCmd.PersistentFlags().SortFlags = false

	copy := *rtcmCmd
	watchCmd.AddCommand(&copy)
	copy2 := *rtcmCmd
	statCmd.AddCommand(&copy2)
}

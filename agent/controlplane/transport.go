package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"kyanos/agent/common"
	kcommon "kyanos/common"

	"google.golang.org/grpc/credentials"
)

// BuildTransport selects and constructs the appropriate gRPC transport
// credentials based on the supplied TLS configuration.
//
// Behaviour (Requirements 8.2, 8.3, 8.4, 8.6):
//
//   - When TLS is enabled and Insecure is false: returns an authenticated,
//     encrypted transport. If CertPath/KeyPath are provided, mutual TLS is
//     configured. If CAPath is provided, it is used to verify the server
//     certificate; otherwise the system CA pool is used.
//
//   - When TLS is enabled and Insecure is true: returns an encrypted transport
//     that skips server certificate verification (no transport authentication).
//
//   - When TLS is enabled, Insecure is false, and required credentials are
//     missing or invalid (e.g. unreadable CA, invalid cert/key pair): returns
//     an error refusing to construct the transport.
//
//   - All log output references credentials by configuration key name only,
//     never by value (Requirement 8.6).
func BuildTransport(cfg common.GRPCTLSConfig) (credentials.TransportCredentials, error) {
	if !cfg.Enable {
		// TLS not enabled — return nil so the caller can use insecure dial
		// (plaintext). This path is not an error; the caller decides whether
		// plaintext is acceptable for its context.
		return nil, nil
	}

	tlsCfg := &tls.Config{}

	// --- Encrypted but no authentication (Requirement 8.3) ---
	if cfg.Insecure {
		kcommon.AgentLog.Debugf("transport: TLS enabled with insecure mode (skip server verification)")
		tlsCfg.InsecureSkipVerify = true
		return credentials.NewTLS(tlsCfg), nil
	}

	// --- Authenticated encrypted transport (Requirement 8.2) ---
	kcommon.AgentLog.Debugf("transport: TLS enabled with server authentication")

	// Load the CA certificate pool for server verification.
	if cfg.CAPath != "" {
		kcommon.AgentLog.Debugf("transport: loading CA certificate from config key \"grpc-ca\"")
		caBytes, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("transport: failed to read CA certificate (config key \"grpc-ca\"): %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("transport: CA certificate (config key \"grpc-ca\") contains no valid PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}

	// Load client certificate and key for mutual TLS if both are provided.
	if cfg.CertPath != "" || cfg.KeyPath != "" {
		// Both must be present for a valid mTLS configuration.
		if cfg.CertPath == "" {
			return nil, fmt.Errorf("transport: client key (config key \"grpc-key\") provided without a client certificate (config key \"grpc-cert\")")
		}
		if cfg.KeyPath == "" {
			return nil, fmt.Errorf("transport: client certificate (config key \"grpc-cert\") provided without a client key (config key \"grpc-key\")")
		}

		kcommon.AgentLog.Debugf("transport: loading client certificate from config key \"grpc-cert\" and key from config key \"grpc-key\"")
		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("transport: failed to load client certificate/key (config keys \"grpc-cert\"/\"grpc-key\"): %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsCfg), nil
}

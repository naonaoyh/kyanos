// Package agentpb contains the generated Go bindings for the Kyanos Agent <->
// Control Plane gRPC contract (proto/agent.proto).
//
// The bindings are committed to the repository so that `GOOS=linux` cross-
// compilation works without requiring protoc or the protoc-gen-go plugins to
// be installed (Requirement 9.3).
//
// To regenerate after editing proto/agent.proto, use the Makefile target:
//
//	make generate-proto
//
// The generation step uses the .protogen helper (pure-Go protocompile front-end)
// and the pre-built plugin binaries in .protogen_bin/. If you have protoc
// installed, you can also run directly:
//
//	protoc --go_out=. --go_opt=module=kyanos \
//	       --go-grpc_out=. --go-grpc_opt=module=kyanos \
//	       proto/agent.proto

package agentpb

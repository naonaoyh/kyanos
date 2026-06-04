package controlplane

import (
	"bytes"

	"kyanos/proto/agentpb"

	"google.golang.org/protobuf/proto"
)

// Redactor is the credential-safety gate. It confirms that a serialized
// SessionEvent does not contain any known secret value before the event is
// allowed to leave the Agent.
//
// This is defense-in-depth on top of structural omission: the event projection
// layer never reads the NTRIP password into any proto field, but the Redactor
// provides a fail-closed secondary check.
type Redactor struct{}

// Confirm returns true if the serialized event provably excludes every
// non-empty secret in the provided list. If any non-empty secret is found in
// the serialized bytes, Confirm returns false and the caller must block the
// event (Requirement 4.9).
//
// Behaviour:
//   - If all secrets are empty (or the list is nil/empty), there is nothing to
//     leak, so Confirm returns true immediately.
//   - If serialization fails, Confirm returns false (fail closed).
//   - Otherwise, the serialized bytes are scanned for each non-empty secret.
//     If any secret appears, Confirm returns false.
//
// Requirements: 4.8, 4.9, 8.1
func (r *Redactor) Confirm(ev *agentpb.SessionEvent, secrets []string) bool {
	// Collect non-empty secrets. If none exist, there is nothing to leak.
	var nonEmpty [][]byte
	for _, s := range secrets {
		if s != "" {
			nonEmpty = append(nonEmpty, []byte(s))
		}
	}
	if len(nonEmpty) == 0 {
		return true
	}

	// Serialize the event. On failure, fail closed.
	data, err := proto.Marshal(ev)
	if err != nil {
		return false
	}

	// Scan for each non-empty secret in the serialized bytes.
	for _, secret := range nonEmpty {
		if bytes.Contains(data, secret) {
			return false
		}
	}

	return true
}

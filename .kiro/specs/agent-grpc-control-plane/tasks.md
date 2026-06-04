# Implementation Plan: Agent gRPC Control Plane (Phase 7)

## Overview

This plan converts the Phase 7 design into incremental Go coding steps. It builds the shared protobuf contract first, then the pure-logic core of the new `agent/controlplane` package (mode gating, resilience primitives, redaction, task/filter state machines, Pod resolution), then the transport and command-routing layer, and finally wires everything into `SetupAgent` behind the `--grpc-server` gate.

Every Phase 7 capability is additive and gated on gRPC mode, so Standalone_CLI_Mode behavior is preserved. The live edges (gRPC peer, K8s API, CRI, `/proc`, the BPF map push) sit behind interfaces so the pure core compiles and is fully testable on the current non-Linux environment; those live paths are deferred-verification items.

Property-based tests use `pgregory.net/rapid` (idiomatic Go generators, standard `testing` integration). Each property test runs at least 100 iterations, implements exactly one design property, and is tagged with a comment in the form:
`// Feature: agent-grpc-control-plane, Property {number}: {property_text}`

Tasks marked with `*` are optional test tasks and can be skipped for a faster MVP.

## Tasks

- [x] 1. Define the shared protobuf service contract and generate Go bindings
  - [x] 1.1 Author `proto/agent.proto`
    - Define `service AgentService` with `Connect`, `ReportEvents`, `ReportStatus`, `StartCapture`, `StopCapture`
    - Define all message types and the `Status` enum: `AgentInfo`, `PodInfo`, `ControlCommand` (oneof), `CaptureTask`, `StopRequest`, `FilterUpdate`, `TaskResponse`, `SessionEvent` (oneof) with `AuthEvent`/`GgaEvent`/`RtcmEvent`/`NetworkEvent`/`SessionCloseEvent`, `ClientAddr`, `AgentStatus`, `EventAck`, `StatusAck`, `NTRIPFilterConfig`, `RTCMFilterConfig`, `ExportOptions`
    - `AuthEvent` MUST have no password field by construction
    - Set `option go_package = "kyanos/proto/agentpb"`
    - _Requirements: 9.5, 2.1, 2.3, 2.6, 3.1, 3.3, 3.4, 3.6, 3.7, 3.8, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 5.1, 5.2, 5.3, 9.2_

  - [x] 1.2 Generate the `proto/agentpb` package and wire generation into the build
    - Add a `protoc` / `protoc-gen-go` / `protoc-gen-go-grpc` generation step (Makefile target or `//go:generate` directive)
    - Commit the generated `*.pb.go` and `*_grpc.pb.go` files so `GOOS=linux` build does not require protoc
    - _Requirements: 9.5, 9.3_

  - [ ]* 1.3 Write property test for protobuf message round-trip
    - **Property 21: Protobuf message round-trip**
    - Generate random instances of each contract message type and assert `Unmarshal(Marshal(m))` equals `m`
    - **Validates: Requirements 9.5**

- [x] 2. Add gRPC options, CLI flags, and mode gating
  - [x] 2.1 Extend `agent/common/options.go` with gRPC option fields
    - Add `GRPCServer string` and a `GRPCOptions` struct (TLS config, pod-resolve toggle, namespace/selector, buffer capacity, backoff max, heartbeat interval/timeout); default zero value = disabled
    - _Requirements: 1.2, 6.1, 6.9, 7.2, 7.3, 7.6, 7.7, 8.2, 8.3, 8.6_

  - [x] 2.2 Implement address validation and the mode-gating predicates
    - Add `validateGRPCServer(addr string) error` and call it from `ValidateAndRepairOptions`; reject startup on empty/invalid address with an error naming the offending value
    - Add `GRPCModeEnabled()` and a Pod-resolution-enabled predicate as pure functions of the options
    - _Requirements: 1.1, 1.5, 1.6, 6.9_

  - [x] 2.3 Add CLI flags and the options-init helper
    - Add persistent flags in `cmd/root.go` (`--grpc-server`, `--grpc-tls`, `--grpc-tls-insecure`, `--grpc-ca/--grpc-cert/--grpc-key`, `--grpc-pod-resolve`, `--grpc-namespace/--grpc-selector`, `--grpc-buffer-capacity`, `--grpc-backoff-max`, `--grpc-heartbeat/--grpc-heartbeat-timeout`)
    - Add a `initGRPCOptions` helper in `cmd/common.go` mirroring `addSessionDiagnosisFlags`/`initSessionDiagnosis`
    - _Requirements: 1.2, 6.1, 6.9, 7.2, 7.3, 7.6, 7.7, 8.2, 8.3, 8.6_

  - [ ]* 2.4 Write property test for mode gating
    - **Property 1: Mode gating is a total function of the flags**
    - Generate random option combinations; assert the gRPC predicates are active iff `GRPCServer` is a non-empty valid address, and Pod resolution is active iff its flag is set
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.6, 6.9**

  - [ ]* 2.5 Write property test for Console address validation
    - **Property 2: Console address validation**
    - Generate valid and invalid address strings (empty, no port, bad port, spaces); assert validation succeeds iff syntactically valid and the error text includes the offending value
    - **Validates: Requirements 1.5**

  - [ ]* 2.6 Write unit test for no-flag standalone compatibility
    - Assert that with `--grpc-server` absent, options yield Standalone_CLI_Mode and no gRPC subsystem is requested (example test for the additive guarantee)
    - _Requirements: 1.3, 1.4_

- [x] 3. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement resilience primitives (Clock, Backoff, EventBuffer)
  - [x] 4.1 Implement `Clock` interface and `Backoff`
    - Add `agent/controlplane/clock.go` with a `Clock` interface (`Now`, `AfterFunc`) plus a real clock and an injectable fake
    - Add `agent/controlplane/backoff.go` implementing `Delay(attempt) = min(Base * Factor^attempt, Max)`
    - _Requirements: 7.1, 7.2_

  - [ ]* 4.2 Write property test for backoff
    - **Property 17: Backoff is monotonic, geometric, and capped**
    - Generate attempt numbers and base/factor/max configs; assert delay equals `min(Base × Factor^n, Max)`, is non-decreasing in n, and never exceeds Max
    - **Validates: Requirements 7.1, 7.2**

  - [x] 4.3 Implement `EventBuffer` (Local_Event_Buffer)
    - Add `agent/controlplane/buffer.go`: bounded ring with `Push` (evict oldest at capacity), `DrainInOrder` (FIFO), `Discarded`, `Len`
    - _Requirements: 7.3, 7.4, 7.5_

  - [ ]* 4.4 Write property test for the event buffer
    - **Property 18: Local event buffer retains newest in order and counts discards**
    - Generate push sequences of length L and capacity C ≥ 1; assert `DrainInOrder` returns the last `min(L, C)` events in push order and the discard counter equals `max(0, L − C)`
    - **Validates: Requirements 7.3, 7.4, 7.5**

- [x] 5. Add the additive granular session event listener
  - [x] 5.1 Define `SessionEventListener` and event value types
    - Add `agent/session/events.go` with the `SessionEventListener` interface (`OnAuthEvent`, `OnGGAEvent`, `OnRTCMEvent`, `OnNetworkEvent`, `OnSessionClose`) and the `GGAEvent`/`RTCMEvent`/`NetworkEventKind` types; keep the `session` package free of any gRPC/`controlplane` dependency
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

  - [x] 5.2 Fire granular events from `SessionTracker`
    - In `agent/session/tracker.go`, fire the new listener callbacks from the existing record handlers (NTRIP request, NMEA sentence, RTCM frame, TCP-health handlers, connection close); keep the existing `SessionListener` callbacks unchanged (tracker fires both)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

  - [ ]* 5.3 Write unit tests for listener firing
    - Register a fake listener and assert each handler fires the matching callback exactly once, including close with no prior events
    - _Requirements: 4.1, 4.6_

- [x] 6. Implement the TaskManager
  - [x] 6.1 Implement `TaskManager`
    - Add `agent/controlplane/task_manager.go`: track active tasks by `task_id`; `Start` validates and records scope + compiled-filter handle + export options and returns an accepting `TaskResponse`, invalid tasks are rejected with a non-empty reason; `Stop` deactivates and returns `STOPPED`, unknown id returns `NOT_FOUND`; arm an injectable-clock duration timer that auto-stops; `TaskIDForSession` maps a session to its owning task; `ActiveTaskIDs` lists active tasks
    - _Requirements: 3.1, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9_

  - [ ]* 6.2 Write property test for capture task lifecycle
    - **Property 5: Capture task lifecycle**
    - Generate valid/invalid `CaptureTask`s, `StopRequest`s, and task-param `FilterUpdate`s; assert tracking/acceptance, rejection-with-reason, stop/NOT_FOUND, and that a task-param update changes only the targeted task
    - **Validates: Requirements 3.1, 3.3, 3.4, 3.6, 3.7, 3.8, 5.3**

  - [ ]* 6.3 Write property test for task duration auto-stop
    - **Property 6: Duration elapses to auto-stop**
    - Using the injected fake clock and positive `duration_seconds`, assert the task is active before the duration elapses and inactive at/after it
    - **Validates: Requirements 3.5**

- [x] 7. Implement event reporting and credential redaction
  - [x] 7.1 Implement the `Redactor`
    - Add `agent/controlplane/redactor.go`: `Confirm(ev, secrets)` returns true only if the serialized event provably excludes every non-empty secret; empty secrets mean nothing to leak (fail closed otherwise)
    - _Requirements: 4.8, 4.9, 8.1_

  - [x] 7.2 Implement `projectEvent` and `EventReporter`
    - Add `agent/controlplane/reporter.go` implementing `session.SessionEventListener`; a single `projectEvent` function maps session state to the matching `SessionEvent` oneof variant, tags `task_id` (via `TaskManager`) and `PodInfo`, preserves the observed client address verbatim, sets timestamp + session id, structurally omits the password, then passes through the `Redactor` gate; on a block, emit a descriptive error unless `silent` is configured; forward accepted events to the `EventBuffer`
    - _Requirements: 3.9, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 8.1, 9.2_

  - [ ]* 7.3 Write property test for event projection
    - **Property 8: Event projection preserves per-variant attributes**
    - Generate sessions with each event kind (including sessions that close with no prior events); assert the oneof variant matches the kind, carries that kind's attributes equal to session state, and close always carries a non-nil summary + disconnect reason
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6**

  - [ ]* 7.4 Write property test for the event envelope
    - **Property 9: Every event carries required envelope fields**
    - Generate any session/event + client addresses; assert every projected event has a non-zero timestamp, non-empty session id, and observed client IP/port equal to the session's (no Cloud_LB transformation)
    - **Validates: Requirements 4.7, 9.2**

  - [ ]* 7.5 Write property test for password exclusion
    - **Property 10: The NTRIP password never leaves the Agent**
    - Generate sessions with arbitrary non-empty passwords, toggling `ShowPassword`/field visibility and echoing the password into adjacent fields; assert no event/export/subsystem-log output contains the password value
    - **Validates: Requirements 4.8, 8.1**

  - [ ]* 7.6 Write property test for the redaction gate
    - **Property 11: Redaction gate soundness**
    - Generate events and inject the secret into arbitrary string fields; assert injected secrets cause "cannot confirm" + block, otherwise forward; an error is emitted iff blocked and silent-blocking is unset
    - **Validates: Requirements 4.9, 4.10**

  - [ ]* 7.7 Write property test for task attribution
    - **Property 7: Events are attributed to the producing task**
    - Generate active tasks with disjoint scopes and a session matching exactly one; assert every projected event carries the matching task's `task_id`
    - **Validates: Requirements 3.9**

- [x] 8. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Implement cgroup whitelist reconciliation
  - [x] 9.1 Implement the `CgroupWhitelist` interface and reconcile function
    - Add `agent/controlplane/cgroup_whitelist.go`: a `CgroupWhitelist` interface abstracting the BPF map (`Update`/`Delete`) and a pure reconcile function computing the desired set `(current ∪ add) \ remove` and the minimal `Update`/`Delete` diff
    - _Requirements: 5.1, 6.4_

  - [ ]* 9.2 Write property test for set reconciliation
    - **Property 15: Cgroup whitelist set reconciliation**
    - Generate current sets + add/remove instructions; assert the reconciled set equals `(current ∪ add) \ remove` and the applied op diff equals the desired−current difference
    - **Validates: Requirements 5.1, 6.4**

- [x] 10. Implement the PodResolver
  - [x] 10.1 Implement `PodResolver` and its lister interfaces
    - Add `agent/controlplane/pod_resolver.go` with `PodLister`/`ContainerLister`/`CgroupMapper`/`CgroupWhitelist` interfaces; `ResolveTargets` lists pods by namespace+selector → container ids → cgroup ids → pushes the whitelist; on push failure emit an error and continue with the resolved status; on K8s-unreachable at startup emit an error and fall back to container-id mode for the process lifetime; `Lookup` returns cached `PodInfo` or reports unresolved without terminating
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8_

  - [ ]* 10.2 Write property test for the cgroup→PodInfo cache
    - **Property 16: cgroup-to-PodInfo cache round-trip**
    - Generate cgroup→PodInfo maps; assert present ids return the exact `PodInfo` and absent ids report unresolved without terminating
    - **Validates: Requirements 6.6, 6.7**

  - [ ]* 10.3 Write edge-case tests for resolver failure handling
    - Inject a failing whitelist push after successful resolution (assert error emitted, cache retained, no termination) and a K8s-unreachable lister at startup (assert fallback to container-id mode for the lifetime)
    - _Requirements: 6.5, 6.8_

  - [ ]* 10.4 Write integration test against fake K8s/CRI/cgroup listers
    - Compose `PodResolver` with in-process fakes and assert end-to-end resolution and whitelist push (live K8s/CRI/`/proc` deferred)
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [x] 11. Implement the FilterController
  - [x] 11.1 Implement `compileFilter`, `filterState`, and `FilterController.ApplyUpdate`
    - Add `agent/controlplane/filter_controller.go`: compile `NTRIPFilterConfig`/`RTCMFilterConfig` into the existing `protocol.ProtocolFilter`; build the next immutable `filterState` from the current one, validate the whole update first, then swap atomically under a mutex (validate-then-commit); reconcile the cgroup whitelist and update task params; on validation failure leave state unchanged; on partial-failure return an error naming the changed components; serialize concurrent updates
    - _Requirements: 3.2, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

  - [ ]* 11.2 Write property test for filter compilation and atomic swap
    - **Property 12: Filter configuration compiles to a semantically matching filter and swaps atomically**
    - Generate filter configs + parsed records; assert the compiled filter accepts a record iff it satisfies the criteria, and after a successful update the active filter is the new one
    - **Validates: Requirements 3.2, 5.2, 5.4**

  - [ ]* 11.3 Write property test for transactional rejection
    - **Property 13: Failed-validation FilterUpdate is transactional**
    - Generate invalid updates over arbitrary starting states; assert active state is unchanged and a descriptive error is returned
    - **Validates: Requirements 5.5**

  - [ ]* 11.4 Write property test for concurrent update serializability
    - **Property 14: Concurrent FilterUpdates serialize to a consistent state**
    - Apply N random updates concurrently (run with `-race`); assert the final state is never torn and equals some sequential application order
    - **Validates: Requirements 5.7**

  - [ ]* 11.5 Write edge-case test for partial application failure
    - Inject a failure after the user-space swap but before the whitelist push; assert the error names the changed components and the already-changed component remains in effect
    - _Requirements: 5.6_

- [x] 12. Implement transport security
  - [x] 12.1 Implement `buildTransport` and the credential loader
    - Add `agent/controlplane/transport.go`: select an authenticated encrypted transport when credentials are present and auth required; an encrypted-only transport when auth is explicitly disabled; return an error refusing construction when required credentials are missing/invalid; reference credentials by configuration key name in logs only
    - _Requirements: 8.2, 8.3, 8.4, 8.6_

  - [ ]* 12.2 Write property test for transport mode selection
    - **Property 19: Transport mode selection**
    - Generate the credential-config space; assert authenticated-encrypted vs encrypted-only vs error-on-missing-required selection
    - **Validates: Requirements 8.2, 8.3, 8.4**

  - [ ]* 12.3 Write property test for credential log exclusion
    - **Property 20: Transport credentials are excluded from logs**
    - Generate random credential values with a captured log sink; assert logs reference credentials by key name only and never contain the values
    - **Validates: Requirements 8.6**

- [x] 13. Implement the command Dispatcher
  - [x] 13.1 Implement `Dispatcher.Dispatch`
    - Add `agent/controlplane/dispatcher.go`: validate and route each inbound `ControlCommand` to the `TaskManager` (start/stop) or `FilterController` (update) by oneof variant; return a descriptive error on unknown/invalid commands so the caller can log and continue
    - _Requirements: 2.3, 2.7_

  - [ ]* 13.2 Write property test for command dispatch
    - **Property 4: Command dispatch routes correctly and continues past bad commands**
    - Generate command sequences across all oneof variants plus malformed commands; assert correct routing per variant and that a bad command yields an error without blocking subsequent well-formed commands
    - **Validates: Requirements 2.3, 2.7**

- [x] 14. Implement the gRPC Client (registration, streaming, heartbeat, reconnect, replay)
  - [x] 14.1 Implement registration/status projection
    - Add `agent/controlplane/registration.go` with `buildAgentInfo` (node name as unique identity, version, managed pods) and `buildStatus` (emit updated managed-pod set + discarded count on change)
    - _Requirements: 2.1, 2.4, 2.6, 9.1_

  - [x] 14.2 Implement the `Client` run loop
    - Add `agent/controlplane/client.go`: `Run(ctx)` dials → registers → serves the bidirectional stream (receive commands → `Dispatcher`; drain `EventBuffer` → send), replays buffered events in order on reconnect before live sends, sends heartbeats at the configured interval, treats a missed heartbeat ack as stream-loss, and reconnects under `Backoff` until ctx is cancelled; retry registration under `Backoff` on rejection; accept commands only over an established authenticated stream; `Enqueue` transports already-redacted events only
    - _Requirements: 2.2, 2.3, 2.5, 7.1, 7.4, 7.6, 7.7, 8.5, 8.7_

  - [ ]* 14.3 Write property test for registration/status projection
    - **Property 3: Registration and status projection carries Agent state verbatim**
    - Generate node/version strings and managed-pod sets; assert `AgentInfo` carries exactly those values (node name as identity) and that differing pod sets produce a status update carrying the new set
    - **Validates: Requirements 2.1, 2.4, 2.6**

  - [ ]* 14.4 Write unit tests for heartbeat timers
    - Using a fake clock, assert a heartbeat is sent at the configured interval and that a missing ack within the timeout triggers reconnection
    - _Requirements: 7.6, 7.7_

  - [ ]* 14.5 Write integration tests against an in-process gRPC server
    - Assert stream establishment over a fake server; assert invalid credentials allow the transport but refuse the stream; assert commands are accepted only over an authenticated stream (live TLS peer deferred)
    - _Requirements: 2.2, 8.5, 8.7_

- [x] 15. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Add the Cgroup_Whitelist BPF map and its concrete binding
  - [x] 16.1 Add `filter_cgroup_map` and the map-backed `CgroupWhitelist`
    - Add the `filter_cgroup_map` hash map to `bpf/pktlatency.bpf.c`, consulted in the filter path and gated by a control value so it stays inert in Standalone_CLI_Mode; add the concrete map-backed `CgroupWhitelist` implementation in `agent/controlplane/cgroup_whitelist_bpf.go` following the `writeFilterNsIdsToMap` precedent (Go binding regeneration via `make build-bpf` and live-kernel filtering are deferred-verification)
    - _Requirements: 5.1, 6.4_

- [x] 17. Wire the subsystem into the Agent and record deferred verification
  - [x] 17.1 Wire `controlplane` into `SetupAgent` behind the gRPC gate
    - In `agent/agent.go` (and `agent/session_wiring.go`), only when `options.GRPCServer != ""`: construct the `PodResolver` and push the initial whitelist before BPF attach, build the `Client`, register the `EventReporter` on the existing `SessionTracker`, and launch `Client.Run` on a goroutine bound to the existing `ctx`/`stopper`; leave the existing cleanup path unchanged
    - _Requirements: 1.1, 1.2, 1.3, 1.6, 2.2, 6.9_

  - [ ]* 17.2 Write unit test for additive wiring
    - Assert the subsystem (Client/Reporter/PodResolver) is nil/inactive when `--grpc-server` is absent and constructed when present, confirming no outbound dial is possible in Standalone_CLI_Mode
    - _Requirements: 1.1, 1.3, 1.6_

  - [x] 17.3 Record deferred-verification items
    - Update `docs/ROADMAP_NEXT.md` Linux/TKE backlog with the deferred-verification items (live stream 2.2, eBPF map push/kernel filtering 6.4, live K8s/CRI/`/proc` 6.1–6.3, TLS handshake/unauthenticated-peer 8.5/8.7, 20+ node DaemonSet rollout 9.1)
    - _Requirements: 9.4_

- [x] 18. Final checkpoint and build-gate verification
  - Run `GOOS=linux go build ./...` and `GOOS=linux go test` for the `controlplane`, `session`, and `proto/agentpb` packages as the build-time verification gate
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 9.3_

## Notes

- Tasks marked with `*` are optional test tasks and can be skipped for a faster MVP.
- Each task references specific requirement sub-clauses for traceability.
- Property tests (`pgregory.net/rapid`, ≥100 iterations each) validate the 21 universal correctness properties; unit/edge/integration tests cover non-universal scenarios and failure-injection behavior.
- Live-dependency criteria (gRPC peer, eBPF map, K8s/CRI/`/proc`, TLS) are deferred-verification items behind interfaces; the pure core compiles and is tested on the current environment.
- The `GOOS=linux` cross-compilation gate (Requirement 9.3) is the contractual proof obligation for this paper deliverable.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "2.1", "4.1", "4.3", "5.1", "9.1"] },
    { "id": 1, "tasks": ["1.2", "2.2", "4.2", "4.4", "5.2", "5.3", "9.2"] },
    { "id": 2, "tasks": ["1.3", "2.3", "2.4", "2.5", "6.1", "10.1", "12.1", "16.1"] },
    { "id": 3, "tasks": ["2.6", "6.2", "6.3", "7.1", "10.2", "10.3", "10.4", "11.1", "12.2", "12.3"] },
    { "id": 4, "tasks": ["7.2", "11.2", "11.3", "11.4", "11.5", "13.1"] },
    { "id": 5, "tasks": ["7.3", "7.4", "7.5", "7.6", "7.7", "13.2", "14.1"] },
    { "id": 6, "tasks": ["14.2", "14.3"] },
    { "id": 7, "tasks": ["14.4", "14.5", "17.1", "17.3"] },
    { "id": 8, "tasks": ["17.2"] }
  ]
}
```

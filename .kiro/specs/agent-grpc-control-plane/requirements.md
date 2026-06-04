# Requirements Document

## Introduction

This document specifies the requirements for **Phase 7** of the Kyanos GNSS troubleshooting platform: the gRPC communication layer between the per-node **Agent** (deployed as a Kubernetes DaemonSet) and a central **Control Plane** (the NTRIP Web Console), together with the Agent refactoring needed to support it.

Kyanos is a secondary-development fork of the upstream eBPF network analysis tool (`hengyoush/kyanos`). Phases 1–6 added NTRIP v1/v2 and RTCM 3.2 protocol parsing, a session-level diagnostic engine (`agent/session`), and structured JSONL session export. Phase 7 upgrades the standalone CLI Agent into a remotely controllable node Agent that can register with a Console, receive capture tasks, report session events in real time, resolve kernel-level events to Kubernetes Pod identities, and survive transient network disruption.

Phase 7 introduces six capability areas:

1. Agent registration and bidirectional gRPC streaming with the Console.
2. Capture task dispatch from Console to specific Agents.
3. Real-time session event reporting from Agent to Console.
4. Runtime-modifiable filter rules without process restart.
5. Pod identity resolution (PodResolver) mapping kernel events to K8s Pod metadata, including pushing a cgroup whitelist to a BPF map for kernel-side filtering.
6. Connection resilience (reconnect with backoff, local buffering with replay, heartbeat).

Two cross-cutting constraints govern the entire phase. First, the **additive, not replacing** principle ("叠加不替换"): gRPC control-plane mode is opt-in via a flag; when disabled, Kyanos behaves exactly as the existing standalone CLI tool. Second, the **credential safety** precedent established in Phase 6: the event/JSONL feed must never carry NTRIP passwords.

The target deployment is Tencent Cloud TKE with 20+ DaemonSet Pods behind a Cloud Load Balancer. Deep Load-Balancer client-IP handling (Proxy Protocol / X-Forwarded-For) is deferred to Phase 10; Phase 7 must not preclude it.

**Verification status:** This is a paper/design deliverable. The current environment cannot run real eBPF or a real Kubernetes cluster. All requirements are written to be explicit and testable, but acceptance criteria that require a live kernel, a live gRPC peer, or a live K8s cluster are designated as deferred-verification items (verified later via `GOOS=linux` build plus the Linux/TKE validation backlog described in `docs/ROADMAP_NEXT.md`).

## Glossary

- **Agent**: The Kyanos process running on a single node (as a DaemonSet Pod in TKE). It loads eBPF programs, captures and parses traffic, and in Phase 7 communicates with the Control Plane. Referred to in requirements as **THE Agent**.
- **Control Plane / Console**: The central NTRIP Web Console backend (Phase 8) that registers Agents, dispatches capture tasks, and receives session events. Referred to as **THE Console**. The Console itself is out of scope for Phase 7; Phase 7 defines only the Agent-side behavior and the shared protobuf contract.
- **gRPC_Client**: The Agent-side component that establishes and maintains the gRPC connection to the Console. Referred to as **THE gRPC_Client**.
- **gRPC_Stream**: The long-lived bidirectional gRPC stream carrying control commands (Console → Agent) and session events (Agent → Console).
- **Registration**: The startup handshake in which the Agent reports its node name, Agent version, and managed DS Pods to the Console and establishes the gRPC_Stream.
- **CaptureTask**: A command from the Console instructing the Agent to begin capturing for a target Pod/namespace/label selector, with NTRIP/RTCM filter configuration, duration, and export options.
- **StopRequest**: A command from the Console instructing the Agent to stop an in-progress capture task.
- **SessionEvent**: A message streamed from the Agent to the Console describing one diagnostic event (authentication, GGA, RTCM, network, or session-close), derived from the `agent/session` diagnostic engine.
- **FilterUpdate**: A command from the Console instructing the Agent to modify active filter rules at runtime.
- **MessageFilter**: The existing user-space `protocol.ProtocolFilter` (e.g. NTRIP mountpoint/username filter, RTCM message-type filter) used to select parsed records.
- **Cgroup_Whitelist**: The set of cgroup IDs written to a BPF map so the kernel-side eBPF program only emits events for targeted Pods.
- **BPF_Map**: An eBPF map used to pass the Cgroup_Whitelist from user space to the kernel-side program for kernel-side filtering.
- **PodResolver**: The Agent component that resolves kernel-level identifiers (PID, cgroup ID) to K8s Pod metadata (name, IP, namespace, node) using the K8s API, the container runtime, and `/proc` cgroup traversal.
- **PodInfo**: The resolved Pod metadata record: Pod name, Pod IP, namespace, node name, container IDs, and cgroup IDs.
- **Standalone_CLI_Mode**: The Agent operating mode in which gRPC control-plane mode is disabled and behavior is identical to upstream Kyanos plus the Phase 1–6 protocol/diagnostic features.
- **gRPC_Mode**: The Agent operating mode enabled by the `--grpc-server` flag, in which the Agent connects to a Console.
- **Local_Event_Buffer**: A bounded local store (in-memory and/or on-disk) holding SessionEvents produced while the gRPC_Stream is disconnected, for later replay.
- **Heartbeat**: A periodic keep-alive signal exchanged over the gRPC_Stream to detect a dead connection.
- **Backoff**: Exponentially increasing delay between reconnection attempts.
- **NTRIP_Password**: The credential extracted from NTRIP Basic Auth or the SOURCE method; classified as a secret that must never leave the Agent in event or export payloads.
- **TKE**: Tencent Cloud Kubernetes Engine, the target deployment environment.
- **Cloud_LB**: The Tencent Cloud Load Balancer in front of the DS Pods. Deep client-IP recovery behind Cloud_LB is a Phase 10 concern.

## Requirements

### Requirement 1: Opt-in additive gRPC mode (additive, not replacing)

**User Story:** As a Kyanos operator, I want the gRPC control-plane integration to be strictly opt-in, so that the existing standalone CLI tool keeps working exactly as before when I do not enable it.

#### Acceptance Criteria

1. WHERE the `--grpc-server` flag is not provided, THE Agent SHALL operate in Standalone_CLI_Mode with behavior identical to the Phase 1–6 build, and SHALL NOT construct any gRPC_Client.
2. WHERE the `--grpc-server` flag is provided with a non-empty Console address, THE Agent SHALL operate in gRPC_Mode.
3. WHILE operating in Standalone_CLI_Mode, THE Agent SHALL NOT open any outbound network connection to a Console.
4. WHERE the `--grpc-server` flag is not provided, THE Agent SHALL preserve the existing exit codes, log output channels, and TUI behavior of the standalone CLI tool.
5. IF the `--grpc-server` flag is provided with an empty or syntactically invalid address, THEN THE Agent SHALL reject startup and SHALL emit a descriptive error identifying the invalid `--grpc-server` value.
6. THE Agent SHALL gate every Phase 7 gRPC capability (Registration, task dispatch, event reporting, FilterUpdate intake) on gRPC_Mode being active.

### Requirement 2: Agent registration and bidirectional streaming

**User Story:** As a Console operator, I want each Agent to register itself and maintain a live bidirectional stream, so that I know which nodes and Pods are available for capture and can send commands at any time.

#### Acceptance Criteria

1. WHEN the Agent starts in gRPC_Mode, THE gRPC_Client SHALL send a registration message containing the node name, the Agent version, and the list of managed DS Pods to the Console.
2. WHEN Registration succeeds, THE gRPC_Client SHALL establish a bidirectional gRPC_Stream for receiving control commands and reporting session events.
3. WHILE the gRPC_Stream is established, THE gRPC_Client SHALL receive control commands of types CaptureTask, StopRequest, and FilterUpdate from the Console.
4. WHEN the Agent's set of managed DS Pods changes WHILE the gRPC_Stream is established, THE Agent SHALL report the updated managed-Pod set to the Console.
5. IF Registration is rejected by the Console, THEN THE Agent SHALL log the rejection reason and SHALL retry Registration subject to the Requirement 9 Backoff policy.
6. THE registration message SHALL identify the Agent uniquely by node name so that the Console can address commands to a specific Agent.
7. IF a received control command has an unrecognized type or fails schema validation, THEN THE Agent SHALL reject the command, SHALL emit a descriptive error, and SHALL continue processing subsequent commands.

### Requirement 3: Capture task dispatch

**User Story:** As a Console operator, I want to push capture tasks to specific Agents, so that I can start and stop targeted NTRIP/RTCM capture on demand without redeploying.

#### Acceptance Criteria

1. WHEN the Agent receives a CaptureTask over the gRPC_Stream, THE Agent SHALL begin capture scoped to the task's target Pod, namespace, and label selector.
2. WHEN the Agent receives a CaptureTask containing NTRIP or RTCM filter configuration, THE Agent SHALL apply that filter configuration to the capture before emitting events for the task.
3. WHEN the Agent accepts a CaptureTask, THE Agent SHALL return a task response that reports acceptance and includes the task identifier from the CaptureTask.
4. IF the Agent rejects a CaptureTask, THEN THE Agent SHALL return a task response that reports rejection and includes a descriptive reason.
5. WHERE a CaptureTask specifies a duration in seconds, THE Agent SHALL stop the capture for that task when the specified duration elapses.
6. WHEN the Agent receives a StopRequest for an active task, THE Agent SHALL stop the capture for the identified task and SHALL return a task response confirming the stop.
7. IF the Agent receives a StopRequest for a task identifier that is not active, THEN THE Agent SHALL return a task response that reports the task as not found.
8. WHERE a CaptureTask specifies export options, THE Agent SHALL apply the requested export options to the task's output.
9. WHILE multiple CaptureTasks are active, THE Agent SHALL associate each emitted SessionEvent with the task identifier of the task that produced it.

### Requirement 4: Session event reporting

**User Story:** As a Console operator, I want the Agent to stream session diagnostic events in real time, so that I can observe authentication, position, correction-stream, network, and disconnect activity as it happens.

#### Acceptance Criteria

1. WHILE a CaptureTask is active, THE Agent SHALL stream SessionEvent messages for authentication, GGA, RTCM, network, and session-close events derived from the diagnostic engine to the Console.
2. WHEN the diagnostic engine records an authentication event for an active task, THE Agent SHALL emit a SessionEvent carrying the authentication outcome and the associated session identifier.
3. WHEN the diagnostic engine records a GGA event for an active task, THE Agent SHALL emit a SessionEvent carrying the GGA position attributes for that event.
4. WHEN the diagnostic engine records an RTCM event for an active task, THE Agent SHALL emit a SessionEvent carrying the RTCM frame attributes for that event.
5. WHEN the diagnostic engine records a network event for an active task, THE Agent SHALL emit a SessionEvent carrying the network-quality attributes for that event.
6. WHEN a session closes during an active task, THE Agent SHALL emit a session-close SessionEvent carrying the disconnect reason and the session summary, regardless of whether that session recorded any prior authentication, GGA, RTCM, or network events.
7. THE Agent SHALL include a timestamp and a session identifier in every SessionEvent.
8. THE Agent SHALL exclude the NTRIP_Password from every SessionEvent, regardless of the diagnostic engine's field-visibility configuration.
9. IF the Agent cannot confirm that a SessionEvent excludes the NTRIP_Password, THEN THE Agent SHALL block that SessionEvent from being sent.
10. WHEN the Agent blocks a SessionEvent due to unconfirmed NTRIP_Password exclusion, THE Agent SHALL emit a descriptive error, EXCEPT WHERE the configuration designates the blocking case as silent, in which case THE Agent SHALL block the SessionEvent without emitting an error.

### Requirement 5: Dynamic filter rules

**User Story:** As a Console operator, I want to change an Agent's filter rules at runtime, so that I can refine what is captured without restarting the Agent and losing in-flight context.

#### Acceptance Criteria

1. WHEN the Agent receives a FilterUpdate that adds or removes target Pods, THE Agent SHALL update the Cgroup_Whitelist in the BPF_Map to match the requested set without restarting the eBPF program.
2. WHEN the Agent receives a FilterUpdate that changes user-space match criteria, THE Agent SHALL replace the active MessageFilter with one reflecting the requested criteria without restarting the Agent process.
3. WHEN the Agent receives a FilterUpdate that changes CaptureTask parameters, THE Agent SHALL apply the changed parameters to the identified active task without restarting the Agent process.
4. WHEN a FilterUpdate is successfully applied, THE Agent SHALL apply the updated rules to records captured after the update takes effect.
5. IF a FilterUpdate fails validation before any component is changed, THEN THE Agent SHALL reject the update, SHALL retain the previously active filter rules unchanged, and SHALL emit a descriptive error.
6. IF a FilterUpdate fails partway through application after one or more filter components have already changed, THEN THE Agent SHALL emit a descriptive error identifying which components changed, and the already-changed components SHALL remain in effect for records captured after the change.
7. THE Agent SHALL serialize concurrent FilterUpdate applications so that the active filter state remains consistent after each update completes.

### Requirement 6: Pod identity resolution (PodResolver)

**User Story:** As a Console operator, I want kernel-level events resolved to Kubernetes Pod identity, so that captured sessions and events are attributed to a named Pod, IP, namespace, and node rather than to opaque kernel identifiers.

#### Acceptance Criteria

1. WHEN the Agent starts in gRPC_Mode with Pod resolution enabled, THE PodResolver SHALL list the Pods matching the configured namespace and label selector using the K8s API.
2. WHEN resolving a Pod, THE PodResolver SHALL obtain the container identifiers for that Pod from the container runtime.
3. WHEN resolving a Pod, THE PodResolver SHALL map container identifiers to cgroup identifiers by traversing `/proc` cgroup information.
4. WHEN the PodResolver has resolved the target cgroup identifiers, THE Agent SHALL push the cgroup identifier list to the BPF_Map as the Cgroup_Whitelist for kernel-side filtering.
5. IF the BPF_Map push fails after the PodResolver has successfully resolved the target cgroup identifiers, THEN THE Agent SHALL emit a descriptive error and SHALL continue with the successful resolution status rather than terminating.
6. WHEN a kernel event carries a cgroup identifier present in the resolver cache, THE PodResolver SHALL resolve that event to a PodInfo containing Pod name, Pod IP, namespace, and node name.
7. IF a kernel event carries a cgroup identifier absent from the resolver cache, THEN THE PodResolver SHALL report the identifier as unresolved and SHALL allow the Agent to continue processing without terminating.
8. IF the K8s API is unreachable at startup, THEN THE Agent SHALL emit a descriptive error and SHALL fall back to the existing container-id based filtering and remain in that mode for the lifetime of the process rather than terminating.
9. THE PodResolver SHALL be activated only WHERE Pod resolution is enabled, so that Standalone_CLI_Mode continues to use the existing container-id based filtering.

### Requirement 7: Connection resilience

**User Story:** As a Console operator, I want the Agent to tolerate transient network loss to the Console, so that node rescheduling or brief outages do not cause lost events or a permanently dead Agent.

#### Acceptance Criteria

1. IF the gRPC_Stream to the Console is lost, THEN THE gRPC_Client SHALL attempt to reconnect using exponentially increasing Backoff delays between attempts.
2. THE gRPC_Client SHALL cap the Backoff delay at a configured maximum so that reconnection attempts continue at a bounded interval.
3. WHILE the gRPC_Stream is disconnected, THE Agent SHALL store generated SessionEvents in the Local_Event_Buffer up to a configured capacity.
4. WHEN the gRPC_Stream is re-established, THE Agent SHALL replay the buffered SessionEvents to the Console in their original order before resuming live event streaming.
5. IF the Local_Event_Buffer reaches its configured capacity, THEN THE Agent SHALL discard the oldest buffered SessionEvents to admit new events and SHALL record the count of discarded events, whether the gRPC_Stream is connected or disconnected.
6. WHILE the gRPC_Stream is established, THE gRPC_Client SHALL send a Heartbeat at the configured interval.
7. IF no Heartbeat acknowledgment is received within the configured timeout, THEN THE gRPC_Client SHALL treat the gRPC_Stream as lost and SHALL initiate reconnection.

### Requirement 8: Control-channel security and credential protection

**User Story:** As a security-conscious operator, I want the control channel protected and credentials kept out of the data feed, so that the troubleshooting platform does not become a credential-leak or unauthorized-control vector.

#### Acceptance Criteria

1. THE Agent SHALL exclude the NTRIP_Password from every SessionEvent, every export payload, and every log message emitted over or on behalf of the gRPC_Stream.
2. WHERE transport credentials are configured for the Console connection, THE gRPC_Client SHALL establish the connection using an authenticated, encrypted transport.
3. WHERE transport credentials exist but transport authentication is explicitly disabled in configuration, THE gRPC_Client SHALL establish an encrypted connection without transport authentication.
4. IF transport credentials are required by configuration but missing or invalid, THEN THE Agent SHALL refuse to establish the gRPC_Stream and SHALL emit a descriptive error.
5. IF the configured credentials are invalid, THEN THE Agent SHALL allow the underlying transport connection to be established but SHALL refuse to establish the gRPC_Stream over it.
6. WHEN the Agent loads Console connection credentials, THE Agent SHALL exclude the credential values from log output, referencing them by configuration key name only.
7. THE Agent SHALL accept control commands only over an established, authenticated gRPC_Stream, so that capture and filter behavior cannot be altered by an unauthenticated peer.

### Requirement 9: Deployment compatibility and deferred verification

**User Story:** As a platform engineer, I want Phase 7 to fit the TKE deployment model and acknowledge what cannot yet be verified, so that later phases (load-balancer handling, Console, integration) can build on it without rework.

#### Acceptance Criteria

1. THE Agent SHALL operate as a node-scoped process suitable for DaemonSet deployment across 20 or more nodes, addressing each Agent by node name.
2. WHERE the Agent runs behind the Cloud_LB, THE Agent SHALL preserve the observed client address fields on each SessionEvent so that later phases can recover the real client IP, without performing Cloud_LB client-IP recovery in Phase 7.
3. THE Phase 7 implementation SHALL compile successfully under `GOOS=linux` cross-compilation as the build-time verification gate.
4. WHERE acceptance criteria require a live kernel, a live gRPC peer, or a live K8s cluster, THE Phase 7 deliverable SHALL document those criteria as deferred-verification items pending Linux/TKE environment availability.
5. THE protobuf service contract SHALL define the Connect, ReportEvents, ReportStatus, StartCapture, and StopCapture operations and the AgentInfo, ControlCommand, CaptureTask, StopRequest, FilterUpdate, and SessionEvent message types so that the Console and Agent share a single source of truth.

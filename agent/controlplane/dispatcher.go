// Package controlplane implements the Phase 7 gRPC control-plane subsystem for
// the Kyanos Agent.
//
// This file implements the Dispatcher: it validates and routes each inbound
// ControlCommand to the appropriate handler by oneof variant (TaskManager for
// start/stop, FilterController for update). Unknown or invalid commands return
// a descriptive error so the caller can log and continue processing subsequent
// commands (Requirement 2.7).
package controlplane

import (
	"errors"
	"fmt"

	"kyanos/proto/agentpb"
)

// FilterApplier is the interface the Dispatcher requires from the
// FilterController. It is defined here to decouple the Dispatcher from the
// concrete FilterController implementation (which may be created concurrently).
type FilterApplier interface {
	ApplyUpdate(u *agentpb.FilterUpdate) error
}

// Dispatcher validates and routes inbound ControlCommands to the TaskManager
// (start/stop) or FilterController (update). It is pure routing logic with no
// live dependencies.
type Dispatcher struct {
	tasks  *TaskManager
	filter FilterApplier
}

// NewDispatcher creates a Dispatcher that routes commands to the given
// TaskManager and FilterApplier. Both dependencies are required; passing nil
// for either will cause Dispatch to return an error for commands that target
// the nil dependency.
func NewDispatcher(tasks *TaskManager, filter FilterApplier) *Dispatcher {
	return &Dispatcher{
		tasks:  tasks,
		filter: filter,
	}
}

// Dispatch validates and routes a single inbound ControlCommand. It returns:
//   - (*TaskResponse, nil) for start_capture and stop_capture commands
//   - (nil, nil) for a successfully applied filter update
//   - (nil, error) for unknown, nil, or invalid commands so the caller can log
//     the error and continue with the next command (Req 2.7)
//
// Requirements: 2.3, 2.7
func (d *Dispatcher) Dispatch(cmd *agentpb.ControlCommand) (*agentpb.TaskResponse, error) {
	if cmd == nil {
		return nil, errors.New("control command is nil")
	}

	switch c := cmd.GetCommand().(type) {
	case *agentpb.ControlCommand_StartCapture:
		return d.handleStartCapture(c.StartCapture)

	case *agentpb.ControlCommand_StopCapture:
		return d.handleStopCapture(c.StopCapture)

	case *agentpb.ControlCommand_UpdateFilter:
		return d.handleUpdateFilter(c.UpdateFilter)

	default:
		// The oneof field is set to a type we don't recognize, or the command
		// field is nil (no variant set). Both are treated as unknown commands.
		return nil, fmt.Errorf("unknown or unset control command variant: %T", cmd.GetCommand())
	}
}

// handleStartCapture routes a CaptureTask to the TaskManager.
func (d *Dispatcher) handleStartCapture(task *agentpb.CaptureTask) (*agentpb.TaskResponse, error) {
	if task == nil {
		return nil, errors.New("start_capture command has nil CaptureTask payload")
	}
	if d.tasks == nil {
		return nil, errors.New("cannot handle start_capture: TaskManager is not configured")
	}
	resp := d.tasks.Start(task)
	return resp, nil
}

// handleStopCapture routes a StopRequest to the TaskManager.
func (d *Dispatcher) handleStopCapture(req *agentpb.StopRequest) (*agentpb.TaskResponse, error) {
	if req == nil {
		return nil, errors.New("stop_capture command has nil StopRequest payload")
	}
	if d.tasks == nil {
		return nil, errors.New("cannot handle stop_capture: TaskManager is not configured")
	}
	resp := d.tasks.Stop(req)
	return resp, nil
}

// handleUpdateFilter routes a FilterUpdate to the FilterController.
func (d *Dispatcher) handleUpdateFilter(update *agentpb.FilterUpdate) (*agentpb.TaskResponse, error) {
	if update == nil {
		return nil, errors.New("update_filter command has nil FilterUpdate payload")
	}
	if d.filter == nil {
		return nil, errors.New("cannot handle update_filter: FilterController is not configured")
	}
	if err := d.filter.ApplyUpdate(update); err != nil {
		return nil, fmt.Errorf("filter update failed: %w", err)
	}
	return nil, nil
}

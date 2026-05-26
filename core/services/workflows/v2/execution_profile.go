package v2

import (
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink/v2/core/services/workflows/events"
)

type executionProfileStep struct {
	stepID       string
	capabilityID string
	startTime    time.Time
	endTime      time.Time
	hasError     bool
}

type executionProfileCollector struct {
	mu    sync.Mutex
	steps []executionProfileStep
}

func newExecutionProfileCollector() *executionProfileCollector {
	return &executionProfileCollector{}
}

func (c *executionProfileCollector) recordStepStart(stepID, capabilityID string, start time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.steps = append(c.steps, executionProfileStep{
		stepID:       stepID,
		capabilityID: capabilityID,
		startTime:    start,
	})
}

func (c *executionProfileCollector) recordStepEnd(stepID string, end time.Time, hasError bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.steps) - 1; i >= 0; i-- {
		if c.steps[i].stepID == stepID && c.steps[i].endTime.IsZero() {
			c.steps[i].endTime = end
			c.steps[i].hasError = hasError
			return
		}
	}
}

func (c *executionProfileCollector) stepsSnapshot() []executionProfileStep {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]executionProfileStep, len(c.steps))
	copy(out, c.steps)
	return out
}

func buildExecutionProfile(
	workflowID string,
	executionID string,
	startTime, endTime time.Time,
	executionStatus string,
	collector *executionProfileCollector,
) events.ExecutionProfile {
	var stepProfiles []events.ExecutionProfileStep
	if collector != nil {
		for _, step := range collector.stepsSnapshot() {
			end := step.endTime
			if end.IsZero() {
				end = endTime
			}
			stepProfiles = append(stepProfiles, events.ExecutionProfileStep{
				StepID:       step.stepID,
				StartTime:    step.startTime.UTC().Format(time.RFC3339Nano),
				EndTime:      end.UTC().Format(time.RFC3339Nano),
				CapabilityID: step.capabilityID,
				HasError:     step.hasError,
			})
		}
	}
	return events.NewExecutionProfile(
		workflowID,
		executionID,
		startTime,
		endTime,
		executionStatus,
		stepProfiles,
	)
}

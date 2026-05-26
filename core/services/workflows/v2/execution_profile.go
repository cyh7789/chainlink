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
	steps map[string]executionProfileStep
	order []string
}

func newExecutionProfileCollector() *executionProfileCollector {
	return &executionProfileCollector{
		steps: make(map[string]executionProfileStep),
	}
}

func (c *executionProfileCollector) recordStepStart(stepID, capabilityID string, start time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.steps[stepID]; !ok {
		c.order = append(c.order, stepID)
	}
	c.steps[stepID] = executionProfileStep{
		stepID:       stepID,
		capabilityID: capabilityID,
		startTime:    start,
	}
}

func (c *executionProfileCollector) recordStepEnd(stepID string, end time.Time, hasError bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	step, ok := c.steps[stepID]
	if !ok {
		return
	}
	step.endTime = end
	step.hasError = hasError
	c.steps[stepID] = step
}

func (c *executionProfileCollector) stepsSnapshot() []executionProfileStep {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]executionProfileStep, 0, len(c.order))
	for _, stepID := range c.order {
		if step, ok := c.steps[stepID]; ok {
			out = append(out, step)
		}
	}
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

	return events.NewExecutionProfile(
		workflowID,
		executionID,
		startTime,
		endTime,
		executionStatus,
		stepProfiles,
	)
}

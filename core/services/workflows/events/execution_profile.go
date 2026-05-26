package events

import (
	"context"
	"encoding/json"
	"time"
)

// ExecutionProfile is emitted to Beholder (Benthos) when a workflow execution completes.
type ExecutionProfile struct {
	WorkflowID          string                    `json:"workflowId"`
	WorkflowExecutionID string                    `json:"workflowExecutionId"`
	StartTime           string                    `json:"startTime"`
	EndTime             string                    `json:"endTime"`
	Status              string                    `json:"status"`
	Steps               []ExecutionProfileStep `json:"steps"`
}

// ExecutionProfileStep describes timing for a single capability step invocation.
type ExecutionProfileStep struct {
	StepID       string `json:"stepId"`
	StartTime    string `json:"startTime"`
	EndTime      string `json:"endTime"`
	CapabilityID string `json:"capabilityId"`
	HasError     bool   `json:"hasError"`
}

func EmitExecutionProfileEvent(ctx context.Context, profile ExecutionProfile) error {
	return emitJSONMessage(ctx, profile, SchemaWorkflowExecutionProfileV2, "workflows.v2."+WorkflowExecutionProfile)
}

func NewExecutionProfile(
	workflowID string,
	executionID string,
	startTime, endTime time.Time,
	status string,
	steps []ExecutionProfileStep,
) ExecutionProfile {
	return ExecutionProfile{
		WorkflowID:          workflowID,
		WorkflowExecutionID: executionID,
		StartTime:           startTime.UTC().Format(time.RFC3339Nano),
		EndTime:             endTime.UTC().Format(time.RFC3339Nano),
		Status:              status,
		Steps:               steps,
	}
}

func emitJSONMessage(ctx context.Context, payload any, schema, entity string) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return emitRawMessage(ctx, b, schema, entity)
}

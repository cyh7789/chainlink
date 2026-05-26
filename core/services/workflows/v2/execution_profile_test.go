package v2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink/v2/core/services/workflows/store"
)

func TestExecutionProfileCollector(t *testing.T) {
	t.Parallel()

	collector := newExecutionProfileCollector()
	start := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	stepEnd := start.Add(50 * time.Millisecond)
	collector.recordStepStart("1", "cap@1.0.0", start)
	collector.recordStepEnd("1", stepEnd, false)

	profile := buildExecutionProfile("workflow-id", "exec-id", start, start.Add(time.Second), store.StatusCompleted, collector)
	require.Equal(t, "workflow-id", profile.WorkflowID)
	require.Equal(t, "exec-id", profile.WorkflowExecutionID)
	assert.Equal(t, store.StatusCompleted, profile.Status)
	require.Len(t, profile.Steps, 1)
	assert.Equal(t, "1", profile.Steps[0].StepID)
	assert.Equal(t, "cap@1.0.0", profile.Steps[0].CapabilityID)
	assert.False(t, profile.Steps[0].HasError)
}

func TestExecutionProfileCollectorInsertionOrder(t *testing.T) {
	t.Parallel()

	collector := newExecutionProfileCollector()
	start := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

	collector.recordStepStart("1", "cap@1.0.0", start.Add(10*time.Millisecond))
	collector.recordStepStart("2", "cap@2.0.0", start.Add(20*time.Millisecond))
	collector.recordStepEnd("1", start.Add(30*time.Millisecond), false)
	collector.recordStepEnd("2", start.Add(40*time.Millisecond), false)

	profile := buildExecutionProfile(
		"workflow-id",
		"exec-id",
		start,
		start.Add(time.Second),
		store.StatusCompleted,
		collector,
	)

	require.Len(t, profile.Steps, 2)
	assert.Equal(t, "1", profile.Steps[0].StepID)
	assert.Equal(t, "2", profile.Steps[1].StepID)
}

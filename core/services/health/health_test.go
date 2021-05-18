package health_test

import (
	"testing"

	"github.com/smartcontractkit/chainlink/core/services/health"
	"github.com/stretchr/testify/assert"
)

func TestWithEmptySetup(t *testing.T) {
	h := health.NewChecker()

	ready, errors := h.IsReady()
	assert.True(t, ready, "empty returns true")
	assert.Empty(t, errors, "empty returns no errors")

	healthy, errors := h.IsHealthy()
	assert.True(t, healthy, "empty returns true")
	assert.Empty(t, errors, "empty returns no errors")
}

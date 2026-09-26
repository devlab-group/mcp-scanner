package app

import (
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/runtime/sandbox"
)

// The executor supplies runtime.timeout when a request has no override
func TestNewRuntimeExecutorAppliesConfiguredTimeout(t *testing.T) {
	exec, err := NewRuntimeExecutor(config.RuntimeConfig{Timeout: config.Duration(45 * time.Second)})
	if err != nil {
		t.Fatalf("NewRuntimeExecutor: %v", err)
	}
	d, ok := exec.(*sandbox.Docker)
	if !ok {
		t.Fatalf("expected *sandbox.Docker, got %T", exec)
	}
	if d.DefaultTimeout != 45*time.Second {
		t.Fatalf("DefaultTimeout = %v, want 45s", d.DefaultTimeout)
	}
}

// An unset timeout preserves the sandbox default
func TestNewRuntimeExecutorLeavesDefaultTimeoutWhenUnconfigured(t *testing.T) {
	exec, err := NewRuntimeExecutor(config.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntimeExecutor: %v", err)
	}
	d := exec.(*sandbox.Docker)
	if d.DefaultTimeout != sandbox.New().DefaultTimeout {
		t.Fatalf("DefaultTimeout = %v, want the sandbox package's own default %v", d.DefaultTimeout, sandbox.New().DefaultTimeout)
	}
}

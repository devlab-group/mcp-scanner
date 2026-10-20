package app

import (
	"fmt"

	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/runtime/sandbox"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

// NewRuntimeExecutor builds the configured sandbox or reports why it is unavailable
func NewRuntimeExecutor(cfg config.RuntimeConfig) (analyzer.RuntimeExecutor, error) {
	if cfg.Backend != "" && cfg.Backend != "docker" {
		return nil, fmt.Errorf("runtime backend %q is not supported", cfg.Backend)
	}
	d := sandbox.New()
	if cfg.Image != "" {
		d.Image = cfg.Image
	}
	if cfg.MemoryMB > 0 {
		d.Memory = fmt.Sprintf("%dm", cfg.MemoryMB)
	}
	if cfg.CPUs > 0 {
		d.CPUs = fmt.Sprintf("%.2f", cfg.CPUs)
	}
	if cfg.PIDLimit > 0 {
		d.PIDsLimit = int64(cfg.PIDLimit)
	}
	if t := cfg.Timeout.Std(); t > 0 {
		d.DefaultTimeout = t
	}
	// Runtime requests normally use this default unless a caller sets a timeout
	return d, nil
}

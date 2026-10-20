// Package app assembles the scanner for the CLI and HTTP API
package app

// Blank imports register analyzers with analyzer.Default. Cisco and VirusTotal
// remain disabled because their API contracts have not been tested live.
import (
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/auth"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	// _ "github.com/devlab-group/mcp-scanner/internal/analyzers/cisco"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/llm"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/promptdefense"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/protocol"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/readiness"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/runtime"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/supplychain"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/taint"
	// _ "github.com/devlab-group/mcp-scanner/internal/analyzers/virustotal"
	_ "github.com/devlab-group/mcp-scanner/internal/analyzers/yara"
)

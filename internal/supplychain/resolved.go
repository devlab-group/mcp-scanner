// Package supplychain holds the seam between the code that downloads a
// package target and the analyzer that has to say something about it
package supplychain

import "github.com/devlab-group/mcp-scanner/pkg/analyzer"

// ResolvedVersionKey publishes the registry version for every resolved package (see
// analyzer.ResolvedVersionKey). It is what OSV is asked about, so a tag such as "latest" never
// reaches it as written.
const ResolvedVersionKey = analyzer.ResolvedVersionKey

// ExtractionDirPrefix names the temporary directory a package target is downloaded and extracted
// into. The CLI and the API both create one, and their tests find leftovers by this prefix.
const ExtractionDirPrefix = "mcp-scanner-package-"

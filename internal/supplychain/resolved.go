// Package supplychain holds the seam between the code that downloads a
// package target and the analyzer that has to say something about it
package supplychain

// ResolvedVersionKey publishes the registry version for every resolved package. The analyzer uses
// it only when Target.Version is empty; an explicit tag such as "latest" still reaches OSV as
// written, so callers should prefer a concrete version.
const ResolvedVersionKey = "supplychain.resolved_version"

// ExtractionDirPrefix names the temporary directory a package target is downloaded and extracted
// into. The CLI and the API both create one, and their tests find leftovers by this prefix.
const ExtractionDirPrefix = "mcp-scanner-package-"

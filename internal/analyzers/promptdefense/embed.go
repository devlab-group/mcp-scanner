package promptdefense

import "embed"

// embeddedRules mirrors rules/prompt-defense/*.yaml at the repository root. The go:embed
// directive cannot reach outside this package's directory tree, so the shipped set is
// copied here: a rules directory found by probing the filesystem is gone once `go install`
// copies the binary elsewhere, or the module cache is pruned. The root rules directory is the
// source of truth, so changes there must be mirrored into rulesdata before release.
//
//go:embed rulesdata/*.yaml
var embeddedRules embed.FS

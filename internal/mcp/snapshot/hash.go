package snapshot

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Hash returns the canonical snapshot's hex-encoded SHA-256 hash. Capability-list, warning, and
// JSON map-key ordering are normalized; ordering inside other slices remains significant.
func Hash(s *model.Snapshot) (string, error) {
	c, err := Canonical(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

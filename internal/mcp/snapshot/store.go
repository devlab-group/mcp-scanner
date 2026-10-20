package snapshot

import (
	"encoding/json"
	"fmt"
	"io"

	reportjson "github.com/devlab-group/mcp-scanner/internal/report/json"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Write encodes s as indented JSON, escaping the same target-controlled characters
// report.Sanitize blocks in every other output the scanner produces
func Write(w io.Writer, s *model.Snapshot) error {
	sanitized, err := reportjson.SanitizedValue(s)
	if err != nil {
		return fmt.Errorf("marshaling snapshot: %w", err)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sanitized)
}

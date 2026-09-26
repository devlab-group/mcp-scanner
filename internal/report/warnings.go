package report

import (
	"fmt"
	"io"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// WriteWarnings prints res.Warnings directly under the verdict line, not at the end of the
// summary: every warning Aggregate builds - a best-effort scan with no required analyzer
// behind it, a non-fatal analyzer error, an invalid finding - exists to qualify what the
// verdict above it is standing on
func WriteWarnings(w io.Writer, res *model.ScanResult) {
	if len(res.Warnings) == 0 {
		return
	}
	fmt.Fprintln(w, "warnings:")
	for _, warning := range res.Warnings {
		fmt.Fprintf(w, "  - %s\n", Sanitize(warning))
	}
}

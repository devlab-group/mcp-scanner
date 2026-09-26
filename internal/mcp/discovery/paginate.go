package discovery

import (
	"context"
	"fmt"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// Caps on any one list method's pagination. A server is untrusted input: without a bound,
// one that always sets NextCursor can grow the scanner's memory without limit, since every
// item is kept and serialized into the result.
var (
	maxListPages = 10000
	maxListItems = 10000
	maxListBytes = 32 * 1024 * 1024 // 32 MiB of item JSON per list method
)

// LimitHitReason prefixes a Truncation.Reason produced by one of paginate's own caps (page,
// item or byte) - the scanner protecting itself - as opposed to a stop caused by the
// server's own behavior (a repeated cursor, a failed page)
const LimitHitReason = "hit the scanner's own "

// paginate drives one list method to the end, or stops early against whichever cap trips
// first: page count, item count, cumulative byte estimate, or a cursor the method has
// already returned - a server that echoes one cursor back is the cheapest version of the
// same attack
func paginate[T any](
	ctx context.Context,
	method string,
	fetch func(ctx context.Context, cursor string) (items []T, nextCursor string, pageBytes int, err error),
) ([]T, *model.Truncation, error) {
	var out []T
	seenCursors := map[string]bool{}
	cursor := ""
	pages := 0
	bytesRead := 0

	truncated := func(reason string) *model.Truncation {
		return &model.Truncation{Method: method, Read: len(out), Unknown: true, Reason: reason}
	}
	limitHit := func(reason string) *model.Truncation {
		return truncated(LimitHitReason + reason)
	}

	for {
		items, next, pageBytes, err := fetch(ctx, cursor)
		if err != nil {
			if len(out) == 0 {
				return nil, nil, err
			}
			return out, truncated(fmt.Sprintf("stopped after %d page(s): %v", pages, err)), nil
		}
		pages++
		// Checked before the page joins out: the byte estimate is for this page alone, and a single
		// page can already be past the cap on its own
		if bytesRead+pageBytes >= maxListBytes {
			return out, limitHit(fmt.Sprintf("%d-byte cap", maxListBytes)), nil
		}
		out = append(out, items...)
		bytesRead += pageBytes

		// next is checked before the item cap: a server whose last page
		// brings the total to exactly the cap and returns no cursor was
		// read to the end, and must not be reported as if the cap cut it
		// off. The cap only matters while there is still more to fetch.
		if next == "" {
			return out, nil, nil
		}
		if len(out) >= maxListItems {
			return out, limitHit(fmt.Sprintf("%d-item cap", maxListItems)), nil
		}
		if seenCursors[next] {
			return out, truncated("server returned a pagination cursor it had already returned"), nil
		}
		seenCursors[next] = true
		if pages >= maxListPages {
			return out, limitHit(fmt.Sprintf("%d-page cap", maxListPages)), nil
		}
		cursor = next
	}
}

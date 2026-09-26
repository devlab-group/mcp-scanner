package discovery

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestPaginateFollowsCursorToTheEnd(t *testing.T) {
	pages := [][]int{{1, 2}, {3, 4}, {5}}
	cursors := []string{"a", "b", ""}
	i := 0
	items, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		got := pages[i]
		next := cursors[i]
		i++
		return got, next, len(got) * 8, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trunc != nil {
		t.Fatalf("expected no truncation for a list that ends cleanly, got %+v", trunc)
	}
	if len(items) != 5 {
		t.Fatalf("got %d items, want 5", len(items))
	}
}

func TestPaginateStopsAtItemCap(t *testing.T) {
	old := maxListItems
	maxListItems = 5
	defer func() { maxListItems = old }()

	calls := 0
	items, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		calls++
		return []int{1, 2}, fmt.Sprintf("cursor-%d", calls), 16, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trunc == nil || !trunc.Unknown {
		t.Fatalf("expected an unknown-size truncation, got %+v", trunc)
	}
	if len(items) < 5 {
		t.Fatalf("got %d items, want at least the cap (5)", len(items))
	}
	if calls > 10 {
		t.Fatalf("paginate made %d calls against a server that never stops offering pages", calls)
	}
}

func TestPaginateRejectsASingleOversizedPage(t *testing.T) {
	old := maxListBytes
	maxListBytes = 100
	defer func() { maxListBytes = old }()

	calls := 0
	items, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		calls++
		return []int{1, 2, 3}, "", 1000, nil // one page, ten times over the cap on its own
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("got %d items, want 0: a page over the byte cap on its own must not be kept", len(items))
	}
	if trunc == nil || !trunc.Unknown {
		t.Fatalf("expected an unknown-size truncation, got %+v", trunc)
	}
	if calls != 1 {
		t.Fatalf("got %d calls, want 1", calls)
	}
}

func TestPaginateCompleteWhenLastPageEndsExactlyAtItemCap(t *testing.T) {
	old := maxListItems
	maxListItems = 5
	defer func() { maxListItems = old }()

	items, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		return []int{1, 2, 3, 4, 5}, "", 40, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trunc != nil {
		t.Fatalf("expected no truncation for a list that ends exactly at the item cap with no cursor, got %+v", trunc)
	}
	if len(items) != 5 {
		t.Fatalf("got %d items, want 5", len(items))
	}
}

func TestPaginateTruncatesWhenExactlyAtItemCapWithMoreToRead(t *testing.T) {
	old := maxListItems
	maxListItems = 5
	defer func() { maxListItems = old }()

	items, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		return []int{1, 2, 3, 4, 5}, "more", 40, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trunc == nil || !trunc.Unknown {
		t.Fatalf("expected an unknown-size truncation, got %+v", trunc)
	}
	if len(items) != 5 {
		t.Fatalf("got %d items, want 5", len(items))
	}
}

func TestPaginateStopsAtByteCap(t *testing.T) {
	old := maxListBytes
	maxListBytes = 100
	defer func() { maxListBytes = old }()

	calls := 0
	_, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		calls++
		return []int{1}, fmt.Sprintf("cursor-%d", calls), 50, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trunc == nil || !trunc.Unknown {
		t.Fatalf("expected an unknown-size truncation from the byte cap, got %+v", trunc)
	}
	if calls > 10 {
		t.Fatalf("paginate made %d calls against a server whose pages never stop growing the byte total", calls)
	}
}

func TestPaginateStopsAtPageCap(t *testing.T) {
	old := maxListPages
	maxListPages = 3
	defer func() { maxListPages = old }()

	calls := 0
	_, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		calls++
		return nil, fmt.Sprintf("cursor-%d", calls), 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trunc == nil || !trunc.Unknown {
		t.Fatalf("expected an unknown-size truncation from the page cap, got %+v", trunc)
	}
	if calls > 10 {
		t.Fatalf("paginate made %d calls against a server returning empty pages forever", calls)
	}
}

// TestPaginateDetectsRepeatedCursor is the cheapest version of the same
// attack: a server that does not even bother minting a new cursor each time
func TestPaginateDetectsRepeatedCursor(t *testing.T) {
	calls := 0
	_, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		calls++
		return []int{calls}, "same-cursor", 8, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if trunc == nil || !trunc.Unknown {
		t.Fatalf("expected an unknown-size truncation from cursor repetition, got %+v", trunc)
	}
	if calls > 3 {
		t.Fatalf("paginate made %d calls before noticing the repeated cursor", calls)
	}
}

func TestPaginateKeepsPartialResultsOnMidStreamError(t *testing.T) {
	calls := 0
	items, trunc, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		calls++
		if calls == 2 {
			return nil, "", 0, errors.New("boom")
		}
		return []int{calls}, fmt.Sprintf("cursor-%d", calls), 8, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 from the page that succeeded", len(items))
	}
	if trunc == nil || !trunc.Unknown {
		t.Fatalf("expected an unknown-size truncation from the failed page, got %+v", trunc)
	}
}

func TestPaginateReturnsErrorWhenFirstPageFails(t *testing.T) {
	_, _, err := paginate(context.Background(), "x/list", func(ctx context.Context, cursor string) ([]int, string, int, error) {
		return nil, "", 0, errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected an error when the very first page fails")
	}
}

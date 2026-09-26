package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

type countingDialer struct {
	mu          sync.Mutex
	attempts    int
	opened      int
	closed      int
	failEvery   int
	cancelAfter int
	cancel      context.CancelFunc
}

func (d *countingDialer) Dial(ctx context.Context, target model.Target) (analyzer.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.attempts++
	n := d.attempts
	d.mu.Unlock()
	if d.failEvery > 0 && n%d.failEvery == 0 {
		return nil, errors.New("simulated dial failure")
	}
	d.mu.Lock()
	d.opened++
	opened := d.opened
	cancel := d.cancel
	cancelAt := d.cancelAfter
	d.mu.Unlock()
	if cancel != nil && cancelAt > 0 && opened == cancelAt {
		cancel()
	}
	return &countingSession{d: d}, nil
}

type countingSession struct{ d *countingDialer }

func (*countingSession) Snapshot() *model.Snapshot { return nil }
func (*countingSession) Call(context.Context, string, any) (json.RawMessage, error) {
	return nil, nil // tools/list "succeeds" with an empty result
}
func (*countingSession) CallTool(context.Context, string, map[string]any) (*analyzer.ToolCallResult, error) {
	return &analyzer.ToolCallResult{Text: []string{"someone"}}, nil
}
func (*countingSession) ReadResource(context.Context, string) (*analyzer.ResourceContent, error) {
	return nil, errors.New("not supported by this fake")
}
func (*countingSession) SessionID() string { return "" }
func (s *countingSession) Close() error {
	s.d.mu.Lock()
	s.d.closed++
	s.d.mu.Unlock()
	return nil
}

func TestAuthClosesEverySessionItOpens(t *testing.T) {
	run := func(t *testing.T, d *countingDialer, ctx context.Context) {
		t.Helper()
		New().Analyze(ctx, unreachableTarget, dialFullMatrixContext(d))
		if d.opened == 0 {
			t.Fatal("expected at least one session to be opened")
		}
		if d.closed != d.opened {
			t.Fatalf("opened %d sessions but closed %d", d.opened, d.closed)
		}
	}

	t.Run("normal", func(t *testing.T) {
		run(t, &countingDialer{}, context.Background())
	})

	t.Run("some dials fail", func(t *testing.T) {
		run(t, &countingDialer{failEvery: 3}, context.Background())
	})

	t.Run("cancelled partway through", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		run(t, &countingDialer{cancelAfter: 3, cancel: cancel}, ctx)
	})
}

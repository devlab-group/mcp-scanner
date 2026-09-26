package evals_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/revinand/mcp-scanner/internal/app"
	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/evals"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

func TestCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "evals")
	cases, err := evals.Load(root)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("the corpus is empty; a benchmark nobody populates is not a benchmark")
	}

	cfg := config.Defaults()
	s := scanner.New(analyzer.Default, app.NewPreparer(cfg), nil)
	opts := scanner.Options{
		Probes:          analyzer.ProbeNone,
		Timeout:         5 * time.Minute,
		AnalyzerTimeout: 90 * time.Second,
		Concurrency:     4,
	}

	report := evals.NewReport()
	for _, c := range cases {

		if c.Class == evals.ClassHoldout {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			out := evals.Run(ctx, s, c, opts)
			report.Add(out)
			for _, p := range out.Problems {
				t.Errorf("%s: %s", c.ID, p)
			}
		})
	}
	t.Log("\n" + report.String())
}

func TestHoldout(t *testing.T) {
	cases, err := evals.Load(filepath.Join("..", "..", "evals"))
	if err != nil {
		t.Fatal(err)
	}
	var held []evals.Case
	for _, c := range cases {
		if c.Class == evals.ClassHoldout {
			held = append(held, c)
		}
	}
	if len(held) == 0 {
		t.Fatal("the holdout set is empty, so it cannot catch the corpus being fitted")
	}

	cfg := config.Defaults()
	s := scanner.New(analyzer.Default, app.NewPreparer(cfg), nil)
	opts := scanner.Options{
		Probes:          analyzer.ProbeNone,
		Timeout:         5 * time.Minute,
		AnalyzerTimeout: 90 * time.Second,
		Concurrency:     4,
	}

	report := evals.NewReport()
	for _, c := range held {
		t.Run(c.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			out := evals.Run(ctx, s, c, opts)
			report.Add(out)
			for _, p := range out.Problems {
				t.Errorf("%s: %s", c.ID, p)
			}
		})
	}
	t.Log("\nholdout: " + report.String())
}

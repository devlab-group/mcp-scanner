# Architecture

The scanner analyzes a live server, source tree, package, or static server
description. Its result contains findings, coverage, status, and a verdict.

## The shape of a scan

```
target
  |
  v
preparation        connect, negotiate, discover capabilities
  |
  v
analyzers          run against a shared analysis context
  |
  v
aggregation        one verdict, computed in one place
  |
  v
policy             pass/fail and an exit code
  |
  v
report             json, sarif, table, summary
```

Selected analyzers run concurrently, with four running at once by default. An
explicit `--analyzers` list preserves the operator's order, but concurrent start
order is not guaranteed. Model-assisted findings are `HEURISTIC` and capped at
`HIGH` severity.

## Status and verdict are separate

- `ScanStatus` says whether the analysis ran: `COMPLETED`, `PARTIAL`, `ERROR`,
  `SKIPPED`.

- `Verdict` says what it found: `SAFE`, `UNSAFE`, `UNKNOWN`.

Only these combinations are produced:

```
COMPLETED + SAFE      required analysis ran, nothing blocking
COMPLETED + UNSAFE    required analysis ran, something blocking
PARTIAL   + UNKNOWN   an analyzer could not finish
ERROR     + UNKNOWN   an analyzer failed
SKIPPED   + UNKNOWN   no analyzer produced usable analysis
```

There is no `PARTIAL + SAFE`: an incomplete scan cannot be safe.

## Where the verdict is decided

`(*model.ScanResult).Aggregate`, and nowhere else. It walks the analyzer
results and applies, in order:

1. no analyzer ran -> `SKIPPED` + `UNKNOWN`
2. a required analyzer errored -> `ERROR` + `UNKNOWN`
3. a required analyzer did not complete -> `PARTIAL` + `UNKNOWN`
4. required coverage does not add up -> `PARTIAL` + `UNKNOWN`
5. every analyzer that ran failed and none was required -> `SKIPPED` + `UNKNOWN`
6. a finding at or above the blocking severity -> `COMPLETED` + `UNSAFE`
7. otherwise -> `COMPLETED` + `SAFE`

Explicitly named analyzers are required unless marked best-effort. A
default-selected analyzer that returns `SKIPPED` or `UNAVAILABLE` excuses
itself; other default-selected failures remain required. Best-effort failures
become warnings.

## Coverage

Every analyzer reports what it looked at: files discovered, parsed, failed and
skipped; symbols and functions found; MCP capabilities discovered, analyzed
and skipped. A skip needs a reason. A file that failed to parse, or a
capability that was discovered but never analyzed, is a gap, and a gap
downgrades the scan.

Known limitation: any recorded skip reason accounts for every file and
capability skip, even when it does not explain each one. The zero-parsed-file
and zero-analyzed-capability floors still apply.

Coverage distinguishes "found nothing" from "looked at nothing."

## Evidence levels

A finding records how the scanner learned it:

| Level | Meaning |
|---|---|
| `HEURISTIC` | a pattern matched |
| `STATIC` | the source was parsed, not grepped |
| `DATAFLOW` | a source-to-sink path was traced |
| `PROTOCOL` | observed protocol behaviour |
| `DYNAMIC` | the target was run |
| `CONFIRMED` | a controlled payload produced the predicted effect |

They rank in that order, except `DATAFLOW` and `PROTOCOL`, which rank equally.

## Discovery and execution are separate

Listing tools, prompts, and resources is discovery. Calling a tool is
execution. Remote scans discover by default.

Active behaviour is controlled by one setting:

- `none`: connect and read declarations
- `safe`: also send malformed or unsupported protocol messages that a
  correct server must reject without side effects
- `tool-calls`: permit tools explicitly allowlisted by name

There is no setting that invokes arbitrary tools on a live server.

## Extension points

Adding an analyzer means implementing one interface and registering it:

```go
type Analyzer interface {
    Name() string
    Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult
}
```

The analysis context provides the snapshot, live session, session dialer,
sandbox executor, model client, and shared artifact store. Interfaces keep
analyzers testable without concrete dependencies.

YARA registers an `UNAVAILABLE` stub when libyara support is absent, so the gap
remains visible.

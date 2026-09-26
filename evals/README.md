# Evaluation corpus

This corpus measures detection quality and catches regressions.

## Layout

```
vulnerable/   must produce a finding
fixed/        the repaired version of a vulnerable case, must be quiet
benign/       ordinary code that must be quiet
holdout/      never used while tuning rules
```

Most vulnerable cases have a minimally changed fixed pair. This shows whether
the detector found the flaw rather than incidental fixture text.

## A case

A directory containing `case.yaml` plus whatever it needs:

```yaml
id: command-injection-001
category: command_injection
notes: A tool argument reaches exec.Command through a two-hop helper.
target:
  kind: source
  path: .
expected:
  vulnerable: true
  minimum_severity: high
  rules: [taint.command_injection]
analyzers: [taint]
```

`notes` is required so future maintainers can understand the fixture.

`expected.rules` requires a specific detector, preventing unrelated findings
from masking a regression. `forbidden_rules` keeps fixed false positives from
returning.

Set `regression: true` on a case for a field bug. Never delete these cases.

## Quality targets

The project targets precision and recall of at least 0.95 for deterministic
HIGH and CRITICAL detectors, and macro F1 of at least 0.85 for semantic
analysis. The test suite does not enforce these aggregate thresholds.

Individual fixtures enforce these rules:

- no known critical vulnerability may become a false negative
- no previously fixed false positive may reappear

## Holdout

Do not read holdout cases while writing or tuning rules. `TestHoldout` runs
with `go test ./...` and reveals overfitting without exposing its cases during
tuning.

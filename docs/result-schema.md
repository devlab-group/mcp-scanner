# Result schema

The JSON writer sanitizes a `model.ScanResult` and sorts object keys before
encoding it. Other report formats derive from the same result and omit detail.

Current schema version: `1.0.0`. Consumers must check `schema_version` before
assuming these field shapes.

All strings escape controls, bidi marks, zero-width characters, separators,
and Unicode tags as ASCII markers such as `\u202e`. Do not decode these
markers as formatting.

Object keys are sorted alphabetically. Do not depend on example field order.

## Top level

```json
{
  "schema_version": "1.0.0",
  "scan_id": "scan_2a020e6f5e0125d9",
  "scanner_version": "1.4.0",
  "target": { "...": "see Target" },
  "status": "COMPLETED",
  "verdict": "SAFE",
  "verdict_reasons": ["all required analyzers completed with full coverage and no blocking findings"],
  "findings": [ "...": "see Finding" ],
  "analyzers": [ "...": "see AnalyzerResult" ],
  "coverage": { "...": "see Coverage" },
  "snapshot": { "...": "see Snapshot" },
  "started_at": "2026-01-01T00:00:00Z",
  "finished_at": "2026-01-01T00:00:05Z",
  "duration_ns": 5000000000,
  "warnings": ["analyzer \"llm\" did not run: SKIPPED"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Semver of this document's shape. |
| `scan_id` | string | Opaque id for this run, `scan_` + 16 hex chars. Stable within a run, not across reruns of the same target. |
| `scanner_version` | string | Build version of the scanner that produced this result. Unstamped CLI builds report `dev`; API results omit it. |
| `target` | object | What was scanned. See [Target](#target). |
| `status` | string | How the *scan* ended. See [Status and verdict](#status-and-verdict). |
| `verdict` | string | What the scan concluded. Only meaningful together with `status`. |
| `verdict_reasons` | array of string | Human-readable reasons behind `verdict`. Always non-empty when `status`/`verdict` are set. |
| `findings` | array of [Finding](#finding) | Every finding from every analyzer, most severe first, then by evidence strength, confidence, and finally id (byte-stable across identical runs). Suppressed findings are included. |
| `analyzers` | array of [AnalyzerResult](#analyzerresult) | One entry per default-selected or explicitly named analyzer. Inapplicable analyzers are recorded as `SKIPPED`. |
| `coverage` | [Coverage](#coverage) | The best view across analyzers, not a sum. See the note under Coverage. |
| `snapshot` | [Snapshot](#snapshot) or omitted | The discovered or synthesized MCP surface. Source and package preparation synthesize it from registrations; other targets populate it through discovery or static input. Omitted when preparation produced none. |
| `started_at`, `finished_at` | RFC 3339 timestamp | Wall-clock bounds of the scan, UTC. |
| `duration_ns` | integer (nanoseconds) | `finished_at - started_at`. Named `_ns` because it is a `time.Duration` underneath; do not assume any other unit. |
| `warnings` | array of string, omitted if empty | Non-fatal notes, including best-effort failures and non-fatal errors from required analyzers. Read these with analyzer status and `verdict_reasons`. |

## Status and verdict

`status` describes completion; `verdict` describes the conclusion. Only five
combinations exist:

| `status` | `verdict` | Meaning for a consumer |
|---|---|---|
| `COMPLETED` | `SAFE` | Every required analyzer finished without a reported coverage gap and found nothing at or above the blocking severity. Treat as a pass, subject to the file-skip limitation under Coverage. |
| `COMPLETED` | `UNSAFE` | Every required analyzer finished; at least one non-suppressed finding is at or above the blocking severity. Treat as a fail; see `findings` for what blocked it. |
| `PARTIAL` | `UNKNOWN` | At least one required analyzer could not finish (timed out, hit a coverage gap) but the scan did not hard-fail. Do **not** treat as a pass - there is no `PARTIAL` + `SAFE`. Re-run, extend the timeout, or treat as inconclusive. |
| `ERROR` | `UNKNOWN` | At least one required analyzer failed outright. Same rule: never treat as a pass. |
| `SKIPPED` | `UNKNOWN` | No analyzer produced a usable result, including when every analyzer that ran failed as best-effort. There is no analysis to act on. |

A malformed finding remains visible but suppressed and fails its analyzer. It
also appears in `analyzers[].errors` and top-level `warnings`. Check analyzer
status before acting on its findings.

`SAFE` means all required analysis ran without a recorded gap and found nothing
blocking. A best-effort failure does not downgrade status; a required failure
does. See Coverage for the file-skip accounting limitation.

`verdict_reasons` explains which of these happened - which analyzer, which
coverage gap, or which finding triggered the result.

An empty static document is rejected during preparation, producing `ERROR /
UNKNOWN`. Empty analyzer coverage on an otherwise valid target prevents a safe
verdict.

## Target

```json
{
  "kind": "remote",
  "name": "example-server",
  "url": "https://example.com/mcp",
  "transport": "streamable",
  "ecosystem": "npm",
  "package": "left-pad",
  "version": "1.0.0",
  "path": "/scan/root"
}
```

`kind` is `remote`, `stdio`, `static`, `source`, or `package`. Only
relevant fields are populated. `headers` and `env` are never serialized
because they may contain credentials.

URLs redact both basic-auth fields before serialization. For example,
`https://user:token@host/mcp` becomes
`https://redacted:redacted@host/mcp`; a bare username becomes
`https://redacted@host/mcp`.

Query values are also redacted except for `transport` and `version`.
`model.Target.MarshalJSON` applies this automatically.

Args redact values for flags ending in `key`, `token`, `secret`, or
`password`, in both `--name value` and `--name=value` forms. Similar words
such as `--keyring` are unchanged. `MarshalJSON` calls
`model.Target.RedactedArgs` automatically.

## Finding

```json
{
  "id": "f_1a2b3c4d5e6f7089",
  "rule_id": "supplychain.osv_vulnerability",
  "category": "known_vulnerability",
  "title": "left-pad@1.0.0 is affected by GHSA-aaaa-bbbb-cccc",
  "severity": "HIGH",
  "confidence": 0.9,
  "evidence_level": "STATIC",
  "file": "package-lock.json",
  "line": 0,
  "tool": "",
  "description": "...",
  "remediation": "Upgrade left-pad to 1.0.1",
  "evidence": [ "...": "see Evidence" ],
  "analyzer": "supplychain",
  "taxonomy": [{"scheme": "GHSA", "id": "GHSA-aaaa-bbbb-cccc", "url": "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"}],
  "suppressed": false,
  "suppression_reason": ""
}
```

| Field | Meaning |
|---|---|
| `id` | Truncated SHA-256 fingerprint of target scope, analyzer, rule, category, location, title, and line. Use it across reruns and for baselines. Moving a line or changing targets changes the id. See [Baseline scope](#baseline-scope). |
| `rule_id` | The specific check that fired, namespaced per analyzer (e.g. `supplychain.osv_vulnerability`, `llm.prompt_injection`). |
| `category` | Broad class (`tool_poisoning`, `command_injection`, `known_vulnerability`, ...). |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. Compared against `--fail-on` and the blocking severity that decides `verdict`. |
| `confidence` | 0..1. A `HEURISTIC` finding at 1.0 remains heuristic. |
| `evidence_level` | `HEURISTIC`, `STATIC`, `DATAFLOW`, `PROTOCOL`, `DYNAMIC`, or `CONFIRMED`. LLM findings are always `HEURISTIC` and capped at `HIGH`. |
| `file`, `line`, `tool` | Where the finding applies: a file path (source/package targets or a lockfile), a line number (0 if not applicable), or an MCP capability name (remote/stdio/static targets). |
| `remediation` | Free text, omitted if the analyzer has nothing specific to suggest. |
| `taxonomy` | External identifiers: `CWE`, `OWASP-LLM`, `MITRE-ATLAS`, `CVE`, `GHSA`, `OSV`. `supplychain` findings always carry the OSV id and, when OSV lists them, the CVE/GHSA aliases. |
| `suppressed` | True when a baseline matches the id. The finding stays visible but does not affect the verdict. |
| `suppression_reason` | The reason string from the baseline entry, when suppressed. |

## Evidence

```json
{
  "level": "DATAFLOW",
  "kind": "taint_path",
  "description": "user input reaches os/exec without sanitization",
  "file": "server.go",
  "line": 42,
  "snippet": "os.exec(userInput)",
  "path": [
    {"kind": "source", "symbol": "input", "file": "a.go", "line": 1, "resolved": true},
    {"kind": "sink", "symbol": "exec", "file": "b.go", "line": 2, "resolved": true}
  ],
  "data": {"score": 0.9}
}
```

Every finding has evidence. `path` is an ordered dataflow list of `source`,
`transform`, `sanitizer`, `unknown`, and `sink` hops. `data` is
analyzer-specific; treat it as opaque unless you support that analyzer.

## AnalyzerResult

```json
{
  "analyzer": "supplychain",
  "status": "COMPLETED",
  "required": true,
  "findings": [ "..." ],
  "warnings": ["requirements.txt: could not parse: ..."],
  "errors": [{"kind": "network", "message": "OSV lookup failed: ...", "fatal": true}],
  "coverage": { "...": "see Coverage" },
  "started_at": "2026-01-01T00:00:00Z",
  "finished_at": "2026-01-01T00:00:02Z",
  "duration_ns": 2000000000
}
```

Each default-selected or explicitly named analyzer has an entry. Inapplicable
analyzers are recorded as `SKIPPED`. Status is `COMPLETED`,
`PARTIAL`, `ERROR`, `SKIPPED`, or `UNAVAILABLE`. Best-effort analyzers have
`required: false`; default-selected analyzers that return `SKIPPED` or
`UNAVAILABLE` are also not required. Their failures add a warning. If every
analyzer fails and none is required, the scan is `SKIPPED/UNKNOWN`; a required
failure makes it `ERROR/UNKNOWN`. Error kinds are `config`, `network`,
`timeout`, `parse`, `internal`, `policy`, and `unavailable`.

## Coverage

```json
{
  "files_discovered": 10,
  "files_parsed": 8,
  "files_failed": 1,
  "files_skipped": 1,
  "skip_reasons": ["1 file in an unsupported language (kotlin)"],
  "mcp_capabilities_discovered": 5,
  "mcp_capabilities_analyzed": 5,
  "mcp_capabilities_skipped": 0,
  "limits_hit": []
}
```

Present per-analyzer, inside `analyzers[]`, and once at the top level.

The top-level block takes the maximum of each counter, not the sum. It is an
optimistic display summary. Use `analyzers[].coverage` for exact coverage.

Because counters are maximized independently, they may not add up. The CLI's
top-level gap summary can therefore under-report. Verdict aggregation always
uses per-analyzer coverage.

Two fields carry the meaning:

`skip_reasons` explains omissions. An unexplained skip downgrades the scan to
`PARTIAL`. Any non-empty list accounts for both file and capability skip
counts, even when its entries do not explain each skip. The zero-parsed-file
and zero-analyzed-capability floors still create gaps. Coarse reason accounting
is a known gap in the scanner's fail-closed behavior.

`limits_hit` records protective caps such as file size, pagination, or response
budgets. Every entry is a coverage gap.

Custom consumers should treat mismatched file totals and each unexplained skip
as gaps. The scanner catches mismatched totals and file skips when
`skip_reasons` is empty, but does not map individual reasons to individual
skips.

## Snapshot

```json
{
  "schema_version": "1.0.0",
  "server_name": "example-server",
  "protocol_version": "2025-06-18",
  "instructions": "...",
  "capabilities": {"tools": {"listChanged": true}, "resources": {}},
  "tools": [{"name": "read_file", "description": "...", "input_schema": {}}],
  "prompts": [{"name": "...", "description": "..."}],
  "resources": [{"uri": "...", "description": "..."}],
  "resource_templates": [],
  "transport": {"kind": "streamable-http", "endpoint": "https://...", "tls": true},
  "warnings": []
}
```

The snapshot is the declared MCP surface used by `compare`, `static`, and
`snapshot`. `capabilities` is passed through as a free-form object.

A prompt has `text` only after successful `--get-prompts`. Use `rendered` to
distinguish an empty body from an unfetched prompt; `render_error` records a
failed request.

Resources use `content`, `fetched`, and `read_error` the same way. Older
snapshots decode absent state fields as false (unknown or unfetched).

`transport.endpoint` contains a redacted URL for HTTP transports and the command
for stdio.

## What a consumer should never do

- Never treat a missing `verdict` field, or any `status` other than
  `COMPLETED`, as equivalent to `SAFE`.

- Never derive a pass/fail decision from `findings` alone without also
  checking `status` - a `PARTIAL` scan can have zero findings and still mean
  "we don't know," not "we looked and found nothing."

- Never expect `target.headers` or `target.env` to appear; code that parses
  this schema should not need to redact them, because they are never there.

## Baseline scope

A finding id includes target identity, so a baseline applies only to the
target where the risk was accepted.

Target identity always comes from the operator:

| Kind | Identity |
|---|---|
| `remote` | the redacted URL |
| `stdio` | command and arguments |
| `static` | operator name, falling back to the capture filename; never the snapshot's self-declared `server_name` |
| `package` | the ecosystem and package name, without the version, so an accepted finding survives a patch bump |
| `source` | target name if supplied; otherwise no added identity because findings already use repository-relative paths and lines |

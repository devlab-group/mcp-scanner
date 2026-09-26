# Analyzers

Each analyzer answers one security question. It must report status, coverage,
and evidence for every finding. `mcp-scanner analyzers` lists available and
missing analyzers.

| Name | Question it answers | Evidence | Active | Needs |
|---|---|---|---|---|
| `protocol` | Does the server follow the protocol, and does it match what it declares? | HEURISTIC, STATIC, PROTOCOL | yes, at `safe` | a connection or a snapshot |
| `auth` | Is authentication actually enforced, and are sessions bound to a user? | PROTOCOL, CONFIRMED | yes | a remote target |
| `promptdefense` | Does the text the server hands a model try to steer it? | HEURISTIC, STATIC | no | nothing |
| `readiness` | Which safety signals is the server not declaring? | HEURISTIC, STATIC | no | nothing |
| `yara` | Do any signatures match the declared text? | STATIC | no | `-tags yara` |
| `source` | Where are the MCP capabilities in this code, and did we see all of them? | STATIC | no | a source tree |
| `taint` | Does caller-controlled input reach something dangerous? | DATAFLOW | no | a source tree |
| `behavioral` | Does the implementation do what the description claims? | STATIC | no | a source tree |
| `runtime` | Can a static suspicion be confirmed by running it? | CONFIRMED | yes, sandboxed | Docker |
| `supplychain` | Are the dependencies or the package itself known-bad? | STATIC | no | network for OSV |
| `llm` | Does a model read the surface as hostile? | HEURISTIC | no | a provider key |


Per-analyzer detail:

- [protocol](protocol.md)
- [auth](auth.md)
- [prompt defense](promptdefense.md)
- [readiness and yara](readiness-and-yara.md)
- [source and behavioral](source-and-behavioral.md)
- [taint](taint.md)
- [runtime](runtime.md), and the [sandbox it runs in](runtime-sandbox.md)

## Required, best-effort, and excused

An analyzer named with `--analyzers` is required. If it does not answer, the
verdict is `UNKNOWN`. A default analyzer may excuse itself when, for example,
its API key or build dependency is absent. It remains in the result but does
not downgrade the scan.

An analyzer listed in `best_effort` is not required, even when explicitly
selected. Its failure remains visible but does not downgrade the scan. Other
analyzer failures do downgrade it.

## Evidence levels

`HEURISTIC` < `STATIC` < `DATAFLOW` = `PROTOCOL` < `DYNAMIC` < `CONFIRMED`.

A model produces `HEURISTIC` evidence and its severity is capped at `HIGH`. It
can support deterministic evidence but cannot outrank it.

## Writing one

Implement the interface, register from `init`, and hold to three rules:
always return a status, always report what you did not look at, and never let
a failure look like a clean result.

## Not registered in this build

`cisco` (Cisco AI Defense) and `virustotal` (known-bad hash lookup) compile and
run tests, but are not registered and never appear in results. Their API
implementations have not been tested against the live services.

Registering either one is uncommenting its blank import in
`internal/app/analyzers.go` and adding its name back to
`knownAnalyzerNames` in `cmd/mcp-scanner/cmd_analyzers.go`.

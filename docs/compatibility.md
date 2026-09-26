# Compatibility

## Transports

| Transport               | Status                 |
| ----------------------- | ---------------------- |
| stdio                   | supported              |
| Streamable HTTP         | supported              |
| Legacy SSE (2024-11-05) | supported, best effort |

HTTP transport defaults to automatic selection: endpoints try Streamable HTTP
first, then SSE. The result records the transport used.

## Protocol versions

The scanner negotiates through the official Go SDK. An unrecognized negotiated
version produces a finding, but the scan continues.

## Target kinds

| Kind      | What it scans                                     |
| --------- | ------------------------------------------------- |
| `remote`  | a live MCP server over HTTP                       |
| `stdio`   | an MCP server launched as a child process         |
| `static`  | a JSON description of a server, no connection     |
| `source`  | a directory of source code                        |
| `package` | a published package coordinate                    |

## Discovered surface

`serverInfo`, protocol version, capability declarations, tools, prompts,
resources, resource templates and server instructions. Lists are paginated to
the end; a truncated list is recorded as a coverage shortfall, not as a
complete list.

Resource contents and rendered prompts are fetched only when requested. Per-item
and total byte limits prevent unbounded snapshots. Reaching a limit creates a
coverage gap.

Use `--read-resources` and `--get-prompts`, or their config equivalents;
omitting them leaves those bodies uncovered. The flags require
`--active-probes safe` or higher. A lower setting is a configuration error.

A prompt with a required argument cannot be fetched because the scanner has no
value to supply. This is reported separately from a prompt that was never
requested.

`static` and `source` targets have no live session, so both flags are rejected.

## Source languages

| Language   | Parsing | MCP registration discovery |
| ---------- | ------- | -------------------------- |
| Go         | yes     | yes                        |
| Python     | yes     | yes                        |
| JavaScript | yes     | yes                        |
| TypeScript | yes     | yes                        |
| Java       | yes     | yes                        |
| Rust       | yes     | yes                        |

Discovery handles direct SDK registration, Python decorators, Java and Rust
annotations, helpers, registration tables and loops, factories, cross-file
definitions, and aliased imports. JavaScript and TypeScript decorators produce
no discovered capability. Discovery does not filter by filename.

Blind spots include unresolved dynamic dispatch, reflection, metaprogramming,
absent generated code, and JavaScript or TypeScript decorators. When a
registration is recognized but its name or description cannot be resolved, the
capability still counts toward coverage and creates a gap.

## Package ecosystems

| Ecosystem    | Dependency vulnerabilities | Package source download |
| ------------ | -------------------------- | ----------------------- |
| Go modules   | yes                        | no                      |
| npm          | yes                        | yes                     |
| PyPI         | yes                        | yes                     |
| Cargo        | yes                        | planned                 |
| Maven/Gradle | planned                    | planned                 |

Vulnerability data comes from OSV. CVE, GHSA and OSV identifiers are preserved
on the finding.

## Optional components

| Component               | Requirement             | Behaviour when absent                          |
| ----------------------- | ----------------------- | ---------------------------------------------- |
| YARA                    | build with `-tags yara` | analyzer reports `UNAVAILABLE` with the reason |
| Runtime confirmation    | Docker                  | analyzer reports `UNAVAILABLE` with the reason |
| Model-assisted analysis | a provider API key      | once opted in, a missing key makes the analyzer `ERROR` |

Absent components stay visible. Runtime confirmation supports only launchable
stdio targets. Source trees and packages are not built, and remote processes
cannot be sandboxed, so those targets are skipped with a reason.

## Output

Formats: `summary`, `table`, `json`, and `sarif`. JSON is versioned and
lossless. SARIF keeps findings, status, verdict, and incomplete-scan reasons,
but omits per-analyzer results, coverage counts, and evidence detail.

## Interfaces

The CLI and HTTP API use the same scanner service.

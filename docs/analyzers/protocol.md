# Protocol analyzer

`protocol` checks a discovered snapshot for MCP conformance. With a live
session and `--active-probes safe` or higher, it also sends malformed or
unsupported requests. Static targets receive passive checks only.

## Passive checks

| Rule | Severity | Meaning |
|---|---|---|
| `protocol.version-missing` | `MEDIUM` | No protocol version was recorded. |
| `protocol.version-unknown` | `MEDIUM`, or `LOW` for a date-shaped value | The version is unknown to this build. |
| `protocol.capability-mismatch` | `MEDIUM` | An advertised list method failed, or an unadvertised capability answered an active probe. |
| `protocol.name-duplicate` | `MEDIUM` | Two tools use the same name. |
| `protocol.name-charset` | `LOW` | A tool name contains characters outside `[A-Za-z0-9_.-]`. |
| `protocol.name-collision` | `LOW` | A name is shared across capability kinds. |
| `protocol.missing-description` | `LOW` | A tool has no description. |
| `protocol.schema-invalid` | `MEDIUM` | `inputSchema` is absent or not an object schema. |
| `protocol.output-schema-invalid` | `LOW` | `outputSchema` is present but not an object schema. |
| `protocol.schema-required-mismatch` | `MEDIUM` or `LOW` | `required` names an unknown property, or prose says an unlisted property is required. |
| `protocol.cross-origin-redirect` | `HIGH` | The server attempted a redirect to another origin. The scanner refused it. |
| `protocol.annotation-conflict` | `HIGH` | `readOnlyHint` is true while the schema accepts execution-shaped arguments. |
| `protocol.resource-uri-unsafe` | `MEDIUM` for `file://`, otherwise `LOW` | A resource URI has no scheme or uses a non-HTTP scheme. |
| `protocol.instructions-large` | `LOW` | Server instructions exceed 8,000 characters. |

Unknown versions include any value outside this build's supported
revision list. A newer date-shaped version is lower severity because the
scanner may simply be older than the server.

The schema prose check is heuristic. `annotation-conflict` checks execution
arguments such as `command`, `shell`, `script`, and `eval`; ordinary reader
arguments such as `path`, `file`, `url`, and `query` are excluded.

## Safe active probes

Each probe has its own timeout and is followed by `ping`. If the connection
does not survive, the analyzer reconnects before continuing. If reconnection
fails, the remaining probes do not run and the result is `PARTIAL`. JSON-RPC
and transport-level error responses count as clean rejection. Closing the
connection without an answer does not.

`protocol.probe-unexpected-answer` (`MEDIUM`) covers:

- success for unknown methods, malformed requests, or type-invalid params;
- accepting an unsupported protocol version without valid negotiation;
- success from `tools/call` for an undeclared tool.

An unadvertised capability that answers successfully produces
`protocol.capability-mismatch` instead.

`protocol.probe-leaks-internals` (`MEDIUM`) detects stack traces, absolute
paths, goroutine dumps, panic text, and address-like values in probe errors.
The patterns are heuristic and can match legitimate path or hexadecimal text.

`protocol.probe-accepted-unanswered` (`MEDIUM`) means a probe timed out or an
HTTP server returned 2xx for the probe request without sending a reply.
`protocol.probe-connection-died` (`HIGH`) means the server closed the
connection or exited instead of answering a probe, or the following ping
failed. Each probe reports it at most once. Heavy load can trigger either
finding without a crash.

The invalid resource URI probe triggers `probe-connection-died` over stdio in
servers built on Go MCP SDK v1.7.0. The SDK puts the URI into its not-found
error with Go string escaping, producing invalid JSON. It then fails to write
the reply and ends the session. Any client can trigger this failure with one
request.

These probes do not invoke declared tools. The tool-shaped probes use invalid
or nonexistent names that a conforming server rejects before dispatch.

## Coverage

Capability coverage comes from the snapshot. A known discovery shortfall
becomes a skipped capability; an unknown shortfall or discovery limit creates a
coverage gap. Active probes affect status and warnings rather than capability
counts. When policy or a missing live session prevents probes, passive analysis
can still complete.

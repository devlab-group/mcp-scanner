# HTTP API

`mcp-scanner-api` exposes the CLI's scanner over HTTP.

## Read this first

API callers choose what the scanner connects to, reads, and sometimes runs.
The default accepts only remote targets. Enabling local or executable targets
requires authentication.

The server binds to loopback at `127.0.0.1:8080`. Set
`MCP_SCANNER_API_ADDR` to expose it, and add access control in front of any
network-facing listener.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/scans` | submit a scan, returns `202` with an id |
| `GET` | `/v1/scans/{id}` | poll for the result |
| `GET` | `/healthz` | liveness, never authenticated |
| `GET` | `/readyz` | readiness, never authenticated |

Submit:

```sh
curl -X POST localhost:8080/v1/scans \
  -H 'content-type: application/json' \
  -d '{"target":{"kind":"remote","url":"https://mcp.example.com/mcp"}}'
```

```json
{"id": "scan_1f3c...", "status": "PENDING"}
```

Beyond `target`, a submission may carry three optional fields:

| Field | Meaning |
|---|---|
| `analyzers` | Restricts the run to these analyzers. An unknown name is accepted with `202`, then the stored scan becomes `ERROR`. The LLM analyzer is enabled when the server config names `llm` in `analyzers` or sets `llm.provider` or `llm.api_key_env`. Otherwise an explicitly requested `llm` scan is incomplete. |
| `fail_on` | the lowest severity that makes `pass` false, or `"none"` to turn the gate off. Defaults to the server's configured threshold. |
| `blocking_severity` | the lowest severity that makes the scan's own `verdict` `UNSAFE`, independent of `fail_on`. |

These thresholds do not change the findings. Because the caller controls
`fail_on`, `pass` represents that caller's gate, not server policy.

Requests cannot set `active_probes`; it is a deployment setting.

Poll:

```sh
curl localhost:8080/v1/scans/scan_1f3c...
```

The response is an envelope with `id`, request `status`, `created_at`, and an
optional failure `message`. Once complete, it also has `result`, `pass`, and
`exit_code`. Its `result` field uses the same versioned document the CLI writes
with `--format json`; see [the result schema](result-schema.md).

## Configuration

All of it is environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `MCP_SCANNER_API_ADDR` | `127.0.0.1:8080` | listen address |
| `MCP_SCANNER_API_CONFIG` | none | path to a scanner config file |
| `MCP_SCANNER_API_ALLOWED_KINDS` | `remote` | comma-separated target kinds this server accepts |
| `MCP_SCANNER_API_TOKEN_ENV` | `MCP_SCANNER_API_TOKEN` | name of the variable holding the bearer token |
| `MCP_SCANNER_API_BASE_DIR` | none | directory that filesystem targets must stay inside |

An unknown allowed kind stops startup.

`MCP_SCANNER_API_CONFIG` sets deployment-wide `active_probes` and
`allow_tool_calls`. Requests cannot override the connection policy created at
startup.

## Target kinds and what enabling one costs you

| Kind | What a submitter gains | Requirements |
|---|---|---|
| `remote` | the scanner connects to a URL they choose | none |
| `static` | the scanner reads a local file they name | token, and a base directory |
| `source` | the scanner reads a local directory they name | token, and a base directory |
| `package` | the scanner downloads and unpacks a package they name | token |
| `stdio` | **the scanner runs a command they name** | token |

Only `stdio` accepts `command` and `args`. Other kinds drop or reject them so
callers cannot use the runtime analyzer to select a host executable.

The API rejects `config`, which can expand into multiple targets and results.

All non-remote kinds require a bearer token. `static` and `source` paths must
resolve within `MCP_SCANNER_API_BASE_DIR`. Invalid sensitive-kind
configurations stop startup.

A `package` target's submitted `path` is ignored. The scanner uses a temporary
directory and removes it after the scan. For source, static, and package
targets, discovery-prefixed errors are replaced with a generic message.
Separately, the configured base directory is replaced with `<base>` wherever
it appears in analyzer errors, warnings, skip reasons, or limit records. Other
paths, such as a package scratch directory, have no blanket redaction
guarantee.

Enabling `stdio` grants callers command execution as the scanner's user.

## Authentication

When the variable named by `MCP_SCANNER_API_TOKEN_ENV` contains a token, every
route except the two health checks requires:

```
Authorization: Bearer <token>
```

The scanner reads one token at startup, compares it in constant time, and never
logs or returns it.

## What the token grants

The token is not scoped. Any holder can submit scans and read any result whose
id they know. Scan ids contain 96 random bits, but the API does not isolate
callers.

If you need results kept apart, run separate instances. Do not hand the same
token to parties that should not read each other's scans.

## Shutdown

On `SIGINT` or `SIGTERM`, the server marks itself not ready and immediately
starts HTTP shutdown, which waits up to 15 seconds for handlers. Clients are
not guaranteed time to observe a `503` from `/readyz`. Accepted scans are not
cancelled or awaited, and stdio children can outlive the API process.

## Reaching private addresses

`allow_private_networks` permits loopback, link-local, and private destinations.
Any caller can then probe the deployment's internal network. Enable it only
when every caller is trusted with that access.

## Retention

Results stay in memory until they exceed the fixed retention window, record
limit, or 256 MiB total size limit. The API binary does not expose a setting for
the size limit. The oldest records leave first. Poll promptly and persist
results you need.

If one result exceeds the size cap, the server drops its `snapshot`, adds a
warning, and keeps its findings, coverage, and decision.

Evicted and unknown ids both return `404`.

Nothing is written to disk, so a restart loses every result.

## Limits

Concurrent scans and total in-flight submissions are both bounded, and request
bodies are capped. By default, four scans run while up to 64 accepted scans may
be pending or running. Further submissions receive `429`.

Fixed listener limits are 10 seconds for headers, 30 seconds for request
bodies, and 2 minutes for idle connections and response writes.

Remote targets can still make scans slow and large within those bounds.

## Errors

Errors omit sensitive details. Precise filesystem failures go to server logs,
not callers.

| Status | Meaning |
|---|---|
| `400` | malformed or oversized body, or a target kind or path this server does not accept |
| `401` | missing or wrong bearer token |
| `404` | no scan with that id, or it has been evicted |
| `429` | too many scans in flight |
| `500` | the server could not allocate a scan id/directory or encode a response |
| `503` | the server is shutting down |

HTTP status does not represent the scan verdict. A completed scan with a
critical finding still returns `200`; read the result body.

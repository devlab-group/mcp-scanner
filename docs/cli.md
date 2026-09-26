# CLI reference

This page covers `mcp-scanner`. The last section covers `mcp-scanner-api`.

`mcp-scanner --version` prints the build's `scanner_version`.

## Global flags

These are the shared scan flags, including for `known-configs --run`.
`snapshot` and `compare` reject every unusable shared flag. `static` and
`source` reject `--read-resources` and `--get-prompts`; other unusable flags may
be accepted. `package` accepts and ignores both fetch flags. Other non-scan
commands may accept shared flags without using them.

| Flag                       | Default                                | Meaning                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--format`                 | `summary`                              | `summary`, `table`, `json` or `sarif`.                                                                                                                                                                                                                                                                                                                   |
| `--output`                 | stdout                                 | Write the report to this file instead of stdout.                                                                                                                                                                                                                                                                                                         |
| `--fail-on`                | `high`                                 | Lowest severity that fails the run (exit 2): `low`, `medium`, `high`, `critical`, or `none` to turn the severity gate off so only an incomplete scan can fail.                                                                                                                                                                                           |
| `--allow-private-networks` | off                                    | Let the scanner connect to loopback, link-local and private addresses. Needed to scan a server on localhost. Warns on stderr while it is in effect.                                                                                                                                                                                                      |
| `--analyzers`              | every applicable analyzer in the build | Comma-separated or repeated. An unknown name is a usage error (exit 1), never a silent no-op.                                                                                                                                                                                                                                                            |
| `--best-effort`            | none                                   | Analyzers named here do not block the verdict if they fail; everything else is required.                                                                                                                                                                                                                                                                 |
| `--config`                 | none                                   | Path to a YAML config file (see `mcp-scanner config`).                                                                                                                                                                                                                                                                                                   |
| `--active-probes`          | `safe`                                 | `none` (read declarations only), `safe` (also send malformed/unsupported protocol messages a correct server must reject harmlessly), `tool-calls` (also permit allowlisted tools).                                                                                                                                                                       |
| `--allow-tool-call`        | none                                   | Repeatable. Tool name permitted to actually be invoked at `--active-probes=tool-calls`, or `*` for any. Required (at least one) when `--active-probes=tool-calls`.                                                                                                                                                                                       |
| `--timeout`                | 10m                                    | Bounds the whole scan.                                                                                                                                                                                                                                                                                                                                   |
| `--concurrency`            | 4                                      | Analyzers run at once.                                                                                                                                                                                                                                                                                                                                   |
| `--baseline`               | none                                   | YAML map of `finding-id: reason`. Matches stay visible but do not block. Finding ids include target identity.                                                                                                                                                                                                                                            |
| `--read-resources`         | off                                    | Fetch resource contents, so a payload inside one is analyzed and not only its name. Needs `--active-probes safe` or higher.                                                                                                                                                                                                                              |
| `--get-prompts`            | off                                    | Render declared prompts, so their text is analyzed and not only their description. Needs `--active-probes safe` or higher.                                                                                                                                                                                                                               |

Precedence, lowest to highest: built-in defaults, the `--config` file, and
command-line flags. Secret settings name environment variables whose values
are read at the point of use. The example under
[`mcp-scanner config`](#mcp-scanner-config) shows common keys; the command
validates and prints resolved structural values and secret variable names, but
not secret values or flags.

## `mcp-scanner remote <url>`

Scan an MCP server reachable over HTTP.

```
mcp-scanner remote https://example.com/mcp --transport streamable --fail-on high
```

`--transport`: `auto` (default), `streamable`, or `sse`.

Connections ignore proxy environment variables and connect directly. See the
[threat model](threat-model.md#the-scanner-does-not-use-a-proxy).

If a server advertises a capability but its list call fails, protocol reports
`protocol.capability-mismatch` at `MEDIUM`. With the default `--fail-on high`,
that finding alone does not fail the severity gate.

## `mcp-scanner stdio -- <command> [args...]`

Scan an MCP server launched as a child process. Everything after `--` is
the command and its arguments.

```
mcp-scanner stdio --fail-on medium -- npx -y some-mcp-server
```

## `mcp-scanner static <snapshot.json>`

Scan without a live connection. Input may be a scanner snapshot or a plain MCP
wire document using fields such as `serverInfo`, `tools`, and `inputSchema`.
Other shapes are rejected.

## `mcp-scanner source <path>`

Scan a directory of source code. `path` becomes the scan root; analyzers
never read outside it.

```
mcp-scanner source ./my-mcp-server --analyzers supplychain,taint
```

## `mcp-scanner package (<npm|pypi> <name> [version] | <npm|pypi>:<name>[@version])`

Download, extract, and scan a published package without running install
scripts or build hooks. `version` defaults to the latest release.

Both positional and `ecosystem:name@version` forms work. For scoped npm names,
the final `@` separates the version:

```
mcp-scanner package npm left-pad 1.0.0 --format sarif --output left-pad.sarif
mcp-scanner package npm:left-pad@1.0.0 --format sarif --output left-pad.sarif
mcp-scanner package npm:@example/mcp-server@1.4.0
```

Download failures produce analyzer errors, scan status `ERROR`, and exit 3.

## `mcp-scanner runtime stdio -- <command>`

Runs the target only inside the sandbox and requires the `runtime` analyzer.
Pass the command-local `--snapshot <file>` option with a trusted or recorded
capability snapshot; without it, runtime is `SKIPPED`, the scan is incomplete,
and the command exits 3. The command must be an absolute, self-contained
executable because the scratch image has no interpreters or dynamic loader.

Set `runtime.enabled: true`. Without an enabled backend, runtime is
`SKIPPED`; when the configured backend is unavailable, it is `UNAVAILABLE`.
Either result makes the scan `UNKNOWN` and exits 3. `runtime` cannot be listed
in `--best-effort` or `best_effort` for this subcommand.

`runtime remote` is rejected because a remote tool call cannot be sandboxed.

## `mcp-scanner known-configs`

Lists servers from common Claude Desktop, VS Code, and Cursor config paths.
It does not connect or launch anything by default.

| Flag              | Meaning                                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `--run`           | Also scan every discovered *remote* server.                                                                                                 |
| `--include-stdio` | With `--run`, also launch and scan discovered *stdio* servers. Without it, a discovered stdio server is listed but skipped, never launched. |

```
mcp-scanner known-configs
mcp-scanner known-configs --run --include-stdio --fail-on high
```

With `--run`, the command returns the highest exit code across targets.
`--output` contains all results: a JSON array, multiple SARIF runs, or
successive table/summary blocks.

The command exits 3 when configuration files were unreadable or discovered
stdio targets were skipped. Listing without `--run` also exits 3 for unreadable
configuration; finding no configured servers by itself exits 0.

## `mcp-scanner snapshot remote <url>` / `mcp-scanner snapshot stdio -- <command>`

Capture the declared MCP surface as JSON for later `static` or `compare` use.

Capture accepts only connection-related global flags: `--config`, `--timeout`,
`--allow-private-networks`, `--active-probes`, `--allow-tool-call`,
`--read-resources`, and `--get-prompts`. It also has its own `--output` flag.

A capture with a list shortfall whose missing count is unknown is still written,
warns on stderr, and exits 3. A known, counted shortfall is written and exits 0.
A connection failure writes no snapshot.

## `mcp-scanner compare <snapshot-a.json> <snapshot-b.json>`

Diffs capabilities and server instructions between two snapshots.

Duplicate names and unencodable schemas are reported as differences.

`--fail-on-change`: exit 2 if any difference is found (otherwise exit 0
regardless of differences; the diff is still printed).

`compare` reads two local files and makes no connection, so it uses none of
the global flags; passing one is a usage error.

## `mcp-scanner config`

Validates and prints the resolved YAML configuration. API keys are stored as
environment variable names. Literal `analyzer_options.<analyzer>.tokens`
values are redacted; prefer `tokens_env`.

```yaml
# example config file
analyzers: [supplychain, taint, llm]
best_effort: [llm, supplychain]
fail_on: high              # or "none" to turn the severity gate off
tolerate_unknown: false    # true lets a scan that could not finish pass anyway
active_probes: safe
allow_private_networks: false   # true to scan a server on localhost or a private address
read_resources: false      # fetch resource contents, so a payload inside one is analyzed and not only its name
get_prompts: false         # render declared prompts, so their text is analyzed and not only their description
rules:
  prompt_defense_dir: ./rules/prompt-defense   # replace matching ids and add new rules
  yara_dir: ./rules/yara                       # replace the embedded YARA set
llm:
  provider: anthropic       # openai | anthropic | bedrock, default anthropic
  model: claude-sonnet-5     # default per provider; Anthropic default is claude-sonnet-5
  api_key_env: ANTHROPIC_API_KEY   # default per provider
  # The "llm" analyzer only runs if you opt in: name it in `analyzers`
  # (above), or set `provider` or `api_key_env` here. An API key sitting in
  # the environment is not opt-in by itself - the declared MCP surface
  # (tool descriptions, prompt text, server instructions) is sent to the
  # provider on every scan once opted in. The scanner warns on stderr once per
  # process. Naming llm in analyzers makes it required unless it is also under
  # best_effort. Opting in only through this block makes a missing or rejected
  # key an ERROR, but a SKIPPED result remains non-required.
baseline:
  f_1a2b3c4d5e6f7089: "accepted risk, ticket SEC-123"
```

`tolerate_unknown` allows incomplete scans to pass. It is off by default.

Custom prompt-defense rules replace matching built-in ids and add new ids.
Custom YARA rules replace the entire embedded set. A missing configured rules
directory fails configuration validation; an empty one fails the analyzer.

Bedrock uses `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (or
`llm.api_key_env`), `AWS_SESSION_TOKEN`, and `AWS_REGION`.

## `mcp-scanner analyzers`

Lists availability, active behavior, requirements, evidence levels, and known
limitations. An untagged build still reports YARA as `IN BUILD: yes` because
its stub is registered; the stub returns `UNAVAILABLE` at scan time.

```
mcp-scanner analyzers
```

`--details` prints descriptions and limitations for each analyzer.

```
mcp-scanner analyzers --details
```

## Exit codes

| Code | Meaning                                                                                                                                                         |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Scan completed and policy passed (`SAFE`, or `UNSAFE` findings all below `--fail-on`, or an incomplete scan when `tolerate_unknown` is set in the config file). |
| 1    | Usage or configuration error: bad flags, an unparseable config file, an unknown `--analyzers` name, an invalid target. Never reached from a scan outcome.       |
| 2    | Scan completed and policy failed: a finding at or above `--fail-on`.                                                                                            |
| 3    | The scan could not determine an answer: `status` was `PARTIAL`, `ERROR` or `SKIPPED`.                                                                           |
| 4    | The scanner itself broke: could not write the report, could not create a required temporary directory, or another internal failure unrelated to the target.     |

A usage failure is exit 1. An inconclusive scan is exit 3. Internal scanner
failure is exit 4.

A completed `UNSAFE` scan can exit 0 when every finding is below `--fail-on`.
Read the verdict when low-severity findings matter.

## CI examples

### GitHub Actions

```yaml
name: mcp-scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - run: go build -o mcp-scanner ./cmd/mcp-scanner
      - name: Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          ./mcp-scanner source . \
            --analyzers supplychain,taint,llm \
            --best-effort llm \
            --fail-on high \
            --format sarif --output results.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

The scan step's own exit code (2 on a policy failure, 3 on an incomplete
scan) fails the job; `if: always()` on the upload step still publishes
whatever SARIF was produced.

### GitLab CI

```yaml
mcp-scan:
  image: golang:1.26
  script:
    - go build -o mcp-scanner ./cmd/mcp-scanner
    - ./mcp-scanner source . --fail-on high --format json --output gl-mcp-scan-report.json
  artifacts:
    when: always
    paths:
      - gl-mcp-scan-report.json
  allow_failure: false
```

`gl-mcp-scan-report.json` is a plain build artifact to inspect, not a
native GitLab security report: GitLab's report widgets expect their own
schema, and this file does not match one.

`allow_failure: false` (the default) means exit codes 2, 3 and 4 all fail
the pipeline; set it to `true` on a job that should only warn.

## `mcp-scanner-api`

HTTP API over the same scanner. No router dependency - stdlib
`net/http.ServeMux` with Go's method+path-parameter routing.

| Endpoint         | Method | Purpose                                                                                                                                                                  |
| ---------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/v1/scans`      | POST   | Submit a target. Returns `202` with `{"id": "...", "status": "PENDING"}`.                                                                                                |
| `/v1/scans/{id}` | GET    | Poll a submission: `status` is `PENDING`, `RUNNING`, `DONE` or `ERROR`; `result` (the [result schema](result-schema.md)) and `pass`/`exit_code` are present once `DONE`. |
| `/healthz`       | GET    | Liveness: `200` whenever the process is up.                                                                                                                              |
| `/readyz`        | GET    | Readiness: `200` unless the server is shutting down.                                                                                                                     |

POST body:

```json
{
  "target": {"kind": "remote", "url": "https://example.com/mcp", "headers": {"Authorization": "Bearer ..."}},
  "analyzers": ["supplychain", "taint"],
  "fail_on": "high"
}
```

`active_probes` is not a request field. How hard the scanner may poke at a
live target is set once for the deployment, in the server's configuration
file, because the connection that enforces it is built at startup and reused
for every request. A body carrying it is refused rather than accepted with
the setting quietly dropped.

`target.headers` is used only to reach the *target*; it is never stored,
logged, or echoed back in any response - this is enforced by `model.Target`
itself marking the field non-serializable, the same guarantee the CLI's
report writers get for free. A stdio target's environment is not a request
field at all.

The request body is bounded (1MB by default); the number of scans actually
running at once is bounded separately (4 by default), and the number of
submissions accepted but not yet finished is bounded too, so a burst of
submissions cannot grow the in-memory store without limit. Pending submissions
form an in-memory queue; there is no database, so a process restart drops every
in-flight and completed record.

### Target kinds and authentication

By default only `remote` targets are accepted: it never starts a local
process or reads an arbitrary local path. `static`, `stdio`, `source` and
`package` are opt-in per deployment
(`MCP_SCANNER_API_ALLOWED_KINDS`, comma-separated, e.g.
`remote,static,stdio`) - a `stdio` target runs whatever command the
submitter names, so treat enabling it as granting remote code execution to
anyone who can reach the API.

Enabling any of `stdio`/`source`/`static`/`package` requires a bearer
token: the server refuses to start otherwise. Set the token in the
environment variable named by `MCP_SCANNER_API_TOKEN_ENV` (default
`MCP_SCANNER_API_TOKEN`), then send it as `Authorization: Bearer <token>`
on every request except `/healthz` and `/readyz`. With no sensitive kind
enabled, no token is required and the API runs unauthenticated - the
"remote only" default is meant to be safe that way.

Enabling `source` or `static` additionally requires `MCP_SCANNER_API_BASE_DIR`:
a submitted path is resolved against it with `filepath.EvalSymlinks` plus a
containment check, and a path that escapes is rejected. There is no
equivalent bound for `package` - enable it only behind a token you
control, on a host you are comfortable a submitter can make outbound
package-registry requests from.

```
MCP_SCANNER_API_ALLOWED_KINDS=remote,static,stdio \
MCP_SCANNER_API_TOKEN=correct-horse-battery-staple \
MCP_SCANNER_API_BASE_DIR=/srv/scannable \
mcp-scanner-api
```

Configuration: `MCP_SCANNER_API_ADDR` (default `127.0.0.1:8080`),
`MCP_SCANNER_API_CONFIG` (a config file, same shape as the CLI's),
`MCP_SCANNER_API_ALLOWED_KINDS`, `MCP_SCANNER_API_TOKEN_ENV`,
`MCP_SCANNER_API_BASE_DIR`.

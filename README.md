# mcp-scanner

A security scanner for Model Context Protocol servers. It scans live servers,
source trees, and packages, and reports both findings and coverage gaps.
`SAFE` requires every required analyzer to finish without a reported coverage
gap:

```
COMPLETED + SAFE      required analysis ran, nothing blocking
COMPLETED + UNSAFE    required analysis ran, something blocking
PARTIAL   + UNKNOWN   an analyzer could not finish
ERROR     + UNKNOWN   an analyzer failed
SKIPPED   + UNKNOWN   no analyzer produced usable analysis
```

Timeouts, crashes, unexplained files, and missing statuses downgrade the scan.
An analyzer error is never self-excusing; only an explicit best-effort policy
can exempt it. A known limitation is that any recorded file-skip reason accounts
for all skipped files, so some incomplete file scans can still be `SAFE`.

## Install

```sh
go install github.com/revinand/mcp-scanner/cmd/mcp-scanner@latest
```

Signature matching requires libyara and a tagged build:

```sh
# Debian, Ubuntu
sudo apt install libyara-dev pkg-config

# Fedora, RHEL
sudo dnf install yara-devel pkgconf-pkg-config

# macOS
brew install yara pkg-config
```

```sh
make build-yara
```

See the [YARA installation guide](https://yara.readthedocs.io/en/stable/gettingstarted.html)
for source builds. If `/usr/local/lib` is outside the linker path, run
`sudo ldconfig` or set `LD_LIBRARY_PATH=/usr/local/lib`. Builds without the
tag report YARA as unavailable.

## Use

Scan a remote server:

```sh
mcp-scanner remote https://mcp.example.com/mcp
```

Scan a trusted stdio server as a child process:

```sh
mcp-scanner stdio -- npx -y @example/mcp-server
```

This runs the target on your machine with your privileges. For untrusted code,
use `source` or `package`, which do not execute it. `runtime stdio` runs only an
absolute, statically linked ELF executable in a container and needs a trusted
snapshot.

Scan the servers declared in your MCP client configuration:

```sh
mcp-scanner known-configs --run
```

`--run` scans remote entries. Stdio entries are skipped unless you also pass
`--include-stdio`, and any skipped stdio entry makes the command exit 3.

Scan a source tree, or a published package:

```sh
mcp-scanner source ./my-mcp-server
mcp-scanner package npm:@example/mcp-server@1.4.0
```

Gate a pipeline:

```sh
mcp-scanner remote https://mcp.example.com/mcp --format sarif --output results.sarif --fail-on high
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | scan completed, policy passed |
| 1 | bad flags or configuration |
| 2 | scan completed, policy failed |
| 3 | scan could not determine an answer |
| 4 | the scanner itself broke |

`--fail-on` defaults to `high`, so a pipeline that never sets it still stops
on a high or critical finding. Pass `--fail-on none` to report without
gating.

Treat exit code 3 as a pipeline failure. It means the scan did not finish.

## What it checks

- MCP protocol conformance, capability declarations against actual behaviour,
  and how the server handles malformed input
- Authentication, token validation and session binding
- Prompt injection, tool poisoning, hidden Unicode and credential harvesting
  in the text a server hands a model
- Source-to-sink dataflow across files, in Go, Python, JavaScript, TypeScript,
  Java and Rust
- Mismatch between what a tool says it does and what its handler reaches
- Dependency vulnerabilities and package contents, without running install
  scripts
- Optional sandboxed confirmation of static findings
- Optional model-assisted review that supplements deterministic evidence

## Scanning safely

By default, the scanner discovers capabilities without invoking real tools.

```sh
--active-probes none        connect and read declarations
--active-probes safe        also send malformed protocol messages a correct server must reject
--active-probes tool-calls  permit tools named with --allow-tool-call
```

`safe` is the default. Its `tools/call` probes use an invalid name or a name
that does not exist, which a conforming server rejects before dispatch.
A loose server may dispatch such a request before validating the name. No
setting invokes arbitrary declared tools on a live server or sends intentionally
destructive requests. The runtime analyzer can invoke declared tools only inside
its sandbox.

## Documentation

- [Architecture](docs/architecture.md)
- [Analyzers](docs/analyzers/README.md)
- [Threat model](docs/threat-model.md)
- [Compatibility](docs/compatibility.md)
- [Result schema](docs/result-schema.md)
- [Command line](docs/cli.md)
- [HTTP API](docs/api.md)

## Development

```sh
make check      # gofmt, vet, test, race, vulnerability scan, version check
make build
```

Three rules hold the design together: `SAFE` must mean the analysis ran,
every finding carries evidence, and every analyzer reports what it did not
look at.

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE). Binaries also include the third-party
components listed in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

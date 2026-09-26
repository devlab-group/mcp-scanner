# Runtime sandbox

`internal/runtime/sandbox` implements runtime confirmation through the Docker
CLI. Supporting packages create canaries, payloads, and observations.

## Container boundary

`buildArgs` constructs the exact `docker create` arguments, and the run then
attaches with `docker start --attach --interactive`. Tests pin these controls:

| Flag | Purpose |
|---|---|
| `--read-only` | Prevent writes outside the work tmpfs. |
| `--user 65532:65532` | Run as non-root. |
| `--cap-drop ALL` | Remove Linux capabilities. |
| `--security-opt no-new-privileges` | Block privilege escalation. |
| `--pids-limit`, `--memory`, `--cpus` | Bound resource use. |
| `--network none` | Deny networking by default. |
| `--tmpfs /work:...,noexec,nosuid,size=N` | Provide bounded writable space. |
| `-v <run dir>:/sandbox:ro` | Mount only scanner-created input, read-only. |

The command never adds `--privileged`, host PID/network access, Docker socket
access, the real home directory, or caller-supplied mounts.

## Staging limits

Each run gets a new temporary directory. A non-absolute command is refused. The
scanner copies the entrypoint into the directory, plants synthetic canaries
through `os.Root`, and mounts the directory at `/sandbox`.

The empty `scratch` image supports only statically linked ELF executables.
Interpreted programs and dynamically linked binaries need runtimes or loaders
that are not present. The runtime analyzer detects these cases and skips them
with a reason.

## Proving that execution started

`RuntimeResult.Started` means the container entrypoint ran, not merely that the
Docker CLI started. `Started` remains false for exit codes 125 through 127,
known entrypoint loader failures, and `docker start` daemon errors. The last
case includes runc refusing an entrypoint staged on a noexec temp directory.
These failures return `ERROR`, never a clean result. If the host temp directory
is mounted noexec, set `TMPDIR` to an executable directory before scanning.

## Canaries and network

The analyzer generates one synthetic credential and file set per analysis and
passes it to every run. The set includes AWS-shaped keys, an SSH key, an API
token, and a database password. No real environment values or home-directory
files are copied.

The configured network mode is `deny`. The sandbox contains an internal
`canary` mode for tests, but configuration rejects it and the analyzer never
selects it.

## Payloads and observations

Payload generation walks one level of a tool's JSON Schema, fills other fields
with valid values, and mutates one property at a time. Each payload includes a
reproducible `MCP-CANARY-...` marker. The scanner does not generate SSRF
payloads because containers have no reachable network endpoint. Other payloads
are inert.

Observation uses bounded stdout/stderr, exit state, and timeouts. It recognizes:

- leaked canary values (`canary_hit`);
- `MCP-OBS:<kind>:<detail>` lines from scanner fixtures, which can report
  `file_read`, `file_write`, `process_exec`, `net_connect` or `dns_query`.

`confirm` accepts both sources for any target. `MCP-OBS:` self-reporting is
a fixture convention, not independent sandbox instrumentation.

When a tool is set, the scanner writes a minimal MCP handshake and `tools/call`
request to stdin and checks stdout for a JSON-RPC response to the `tools/call`
id. A reply to the handshake alone does not count, so a target that crashes on
the call is not recorded as having run the tool.

## Cleanup and image build

A deferred `docker rm -f` removes the container after success, cancellation,
or timeout. Separate PID namespaces ensure removing PID 1 also removes child
processes. `SIGKILL` of the scanner can bypass cleanup.

`docker create` runs separately under a 30-second timeout that is independent
of the scan context. Cleanup is registered before creation and attempts to
remove the named container whenever the function exits.

The scanner checks for its base image on every run. Missing images are built
under a mutex, but failures are not cached, so a temporary daemon or disk
failure does not disable later scans.

## Out of scope

The sandbox does not protect against:

- kernel or container-runtime escapes;
- scanner termination by `SIGKILL`;
- computation that needs no external access, beyond resource and time limits;
- timing, cache, and other side channels.

Docker-backed fixtures under `testdata/runtime` cover hostile behavior,
timeouts, traversal, command injection, and benign execution. Argument-level
tests still verify containment flags when Docker is unavailable.

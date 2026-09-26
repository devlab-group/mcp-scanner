# Runtime analyzer

`runtime` executes fuzzed tool calls through the configured sandbox and reports
observed effects. Its findings use `CONFIRMED` evidence. A run without an
observation is coverage, not proof that the tool is safe.

## Requirements

The analyzer proceeds only when:

1. a runtime executor is configured and available;
2. the target is launchable under scanner control;
3. `target.Command` is an absolute, statically linked ELF executable;
4. at least one tool was discovered.

Remote targets are never runtime-tested because their processes are outside the
sandbox. Static and config targets are not runnable. Source and package targets
need a resolved entrypoint, which target preparation does not infer.

The scratch-based sandbox cannot run interpreters or dynamically linked
binaries. The analyzer detects known interpreters and ELF `PT_INTERP` before
calling Docker. Unreadable or unsupported executable formats are skipped with a
reason. See the [runtime sandbox](runtime-sandbox.md).

## Candidate selection

Candidates come from the prepared snapshot. For `runtime stdio`, that snapshot
comes from live discovery or `--snapshot`. Dangerous terms in names,
descriptions, and schema properties determine run order but do not produce
findings.

For each candidate, payload generation mutates one fuzzable property at a time
and fills other schema fields with valid values. One synthetic canary set is
shared across the analysis so observations can be tied to the run.

## Confirmed signals

A finding requires one of these observations from the exact payload run:

- a planted canary value appears in captured output;
- a self-reported `MCP-OBS:` line for `process_exec`, `file_read`, `file_write`,
  `net_connect`, or `dns_query` contains that payload's marker.

The sandbox does not instrument process, file, or network activity. These
`MCP-OBS:` observations are target-provided evidence and can be forged.

Merely echoing the payload in stdout or stderr is not confirmation.

| Payload class | Rule | Severity |
|---|---|---|
| command injection or shell metacharacters | `runtime.command_injection_confirmed` | `CRITICAL` |
| path traversal or file URI | `runtime.path_traversal_confirmed` | `HIGH` |
| template injection | `runtime.template_injection_confirmed` | `HIGH` |
| other canary exposure | `runtime.canary_exposure_confirmed` | `HIGH` |
| other marker-bearing effect | `runtime.effect_confirmed` | `MEDIUM` |

SSRF is not confirmed. Containers have no network, so the scanner generates no
SSRF payloads.

## Status and coverage

Each candidate is discovered, then either analyzed or skipped with a reason.
Unfuzzable schemas, scan deadlines, per-run timeouts, killed or crashed runs
without confirmation, and runs with no JSON-RPC response make the result
`PARTIAL`. One successful case does not compensate for another incomplete case
for the same tool.

`runtime.network` may be omitted or set to `deny`; containers always run with
no network.

- `SKIPPED`: a requirement was not met or there were no candidates.
- `UNAVAILABLE`: the configured runtime backend is unavailable.
- `ERROR`: sandbox execution failed or claimed it never started without an
  error explaining why.
- `PARTIAL`: at least one candidate or payload case did not complete.
- `COMPLETED`: every candidate ran to a result.

Unit tests cover gating and confirmation with a fake executor. Docker-backed
tests cover command injection, path traversal, timeouts, benign execution, and
sandbox failure when a daemon is available.

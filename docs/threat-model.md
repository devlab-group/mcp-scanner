# Threat model

This document covers threats in MCP targets and threats to the scanner while
it processes hostile input.

## Part one: threats in an MCP target

### Trust boundaries

```
operator / CI            trusted
scanner process          trusted
operator-supplied config trusted (CLI or API deployment)
------------------------------------- boundary
HTTP API callers         untrusted
MCP server responses     untrusted
tool and prompt text     untrusted
resource contents        untrusted
scanned source code      untrusted
downloaded packages      untrusted
archive contents         untrusted
model provider output    untrusted
```

Everything below the line is untrusted data, never an instruction or code to
run.

Only operator-supplied CLI or API deployment configuration is trusted. API
callers control what the scanner connects to, reads, or executes. The API
therefore allows only remote targets by default and requires a bearer token
before enabling targets that read local files or start processes. See
[HTTP API](api.md).

### What is being defended

An MCP server can send a model hidden text and act with the user's credentials.

| Class | What it looks like |
|---|---|
| Tool poisoning | A tool description that instructs the model to do something other than what the tool is for |
| Prompt injection | Instruction-override text in descriptions, prompt bodies, resource contents or server instructions |
| Hidden content | Zero-width characters, bidi overrides, confusables, HTML comments carrying instructions the operator cannot see |
| Credential harvesting | A tool that asks for keys, or a handler that reads `~/.ssh`, `.env`, or cloud credential paths |
| Exfiltration | A handler that sends data to a host unrelated to its stated purpose |
| Command injection | Tool arguments reaching a shell |
| Path traversal | Tool arguments reaching the filesystem without a containment check |
| Server-side request forgery | Tool arguments reaching an outbound request, including cloud metadata endpoints |
| Confused deputy | A server forwarding the caller's token to a third party |
| Broken authorization | Tokens accepted without audience, issuer, expiry or scope validation |
| Session weakness | Guessable session ids, sessions not bound to a user, session fixation, session reuse |
| Protocol abuse | Capability declarations that do not match behaviour, malformed responses, crashes on invalid input |
| Rug pull | A server that behaves one way at review time and changes after approval |
| Supply chain | A vulnerable or malicious dependency, or install-time code in a published package |

### What is deliberately not covered

- Vulnerabilities in the model or the client application rather than the MCP
  server.

- Business-logic flaws that need domain knowledge the scanner does not have.

- Anything requiring destructive calls against a production server. The
  scanner will not do this, at any setting.

- Denial-of-service testing of a target.

## Part two: threats to the scanner

Parsing JSON, walking trees, extracting archives, and sending text to a model
all expose the scanner to hostile input.

| Threat | Control |
|---|---|
| Scanned code executes during a static scan | Nothing is executed. Package acquisition downloads and unpacks; it never runs an install script, a `setup.py`, or a build backend hook. |
| Scanned code executes during a live scan | Not defended, by necessity. A `stdio` scan starts the target as a child process on the host, because that is the only way to speak to it. See the note below. |
| Archive path traversal | Every entry path is validated against the extraction root. Absolute paths, `..` segments, symlink and hardlink escapes and device nodes are rejected. |
| Archive bomb | Limits on compressed size, uncompressed size, file count, individual file size and nesting depth. |
| Symlink escape during a source scan | The scan root is a hard boundary. A symlink leaving it is not followed. |
| Symlink fan-out during a source scan | A directory holding several symlinks to itself, or reachable through more than one path, is walked once: the walk tracks every canonical directory it has already read and refuses to read one twice. The tree walk also honours the scan deadline itself, not only the parse pass that follows it. |
| Scanner-initiated request forgery | Every outbound request goes through one guarded client. The check runs in the dialer against the address the kernel is about to connect to, not against an earlier lookup, so a name that resolves differently the second time gains nothing. Scheme allowlist; loopback, link-local, private, carrier-grade NAT and the IPv4-carrying IPv6 translation prefixes refused unless `--allow-private-networks` is passed. Cross-origin redirects are refused, and configured headers are pinned to their origin. |
| Prompt injection against the model analyzer | Untrusted content is fenced and labelled as data. The model has no tools, no filesystem, no MCP access and no network beyond the provider API. Its output can only produce findings, never actions. |
| Secret leakage | API keys are read from the environment at the point of use, never stored in a serializable struct, never logged, and never written to a report. Authorization evidence contains only the `Bearer` scheme and header length, never token characters. |
| Provider API key sent in the clear | Every request to a model provider, Cisco AI Defense, or VirusTotal carries an API key, and an operator-supplied `base_url` or `endpoint` could use plain HTTP. HTTPS is required by default; the LLM provider, Cisco, and VirusTotal options allow HTTP only when their own `allow_insecure_endpoint` setting is explicit. |
| Terminal injection and display spoofing | Anything that came from the target is escaped before it reaches a terminal or a report: every C0 control and DEL, the bidi direction overrides and standalone bidi marks, the line/paragraph separators, the zero-width characters and BOM, the soft hyphen, the combining grapheme joiner, the Mongolian vowel separator, the variation selectors, and the Unicode tags block. Escaping only the control codes leaves a file name that renders as a different name, or two tool names that differ only by an invisible suffix rendering identically. |
| Resource exhaustion | File sizes and counts, MCP pagination, resource reads, archive extraction, analyzer and scan duration, concurrency, and API storage are bounded. Data-loss limits become coverage gaps; concurrency and result-store limits reject or evict work instead. |
| Process and goroutine leaks | Child processes are reaped on cancellation. Sandbox containers are removed even when the scan is interrupted. |
| Sandbox escape | Read-only root, non-root user, all capabilities dropped, no new privileges, no host PID namespace, no host network, no docker socket, no host mounts, bounded CPU, memory, PIDs and wall clock. A kernel-level container escape is out of scope and is stated as such. |
| Host secrets reaching the sandbox | Only synthetic canary values are planted. Nothing is copied from the real environment. |

### The scanner does not use a proxy

The guarded client ignores proxy environment variables. Its dial guard cannot
inspect destinations beyond a proxy.

On proxy-only networks, outbound scans fail closed. When a proxy environment
variable is set, the error names that setting.

### A stdio scan runs the target

`mcp-scanner stdio` and `known-configs --run --include-stdio` launch the target
on the host with the operator's privileges.

`mcp-scanner runtime stdio` runs only inside a container and skips live
discovery. Supply `--snapshot` with a trusted or recorded capability capture.
Without one, runtime is `SKIPPED` and the scan is `UNKNOWN`.

The child receives `PATH` and its explicitly declared environment. This keeps
ambient host secrets out, but it is not a sandbox: the process still has the
operator's privileges.

The child resolves `npx`, `python`, interpreters, and subprocesses through the
operator's real `PATH`, including user-controlled directories.

- `npx -y some-mcp-server` downloads and runs the package. Use `package` or
  `source` to inspect untrusted code without executing it.

- `known-configs` requires two flags before starting a discovered server.

For an untrusted stdio target, `runtime stdio --snapshot` applies only when the
command is an absolute, statically linked ELF executable. Other commands are
skipped. Use the host-based commands only for targets you trust.

## Result integrity

Status, verdict, and coverage are separate so a required analyzer failure cannot
look like a clean result. Only explicit best-effort policy can exempt a failure.

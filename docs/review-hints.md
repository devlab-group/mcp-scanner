# Review hints

Static analysis cannot settle everything. A review hint records a place where the scanner saw
something it could not decide - even a weak suspicion with nothing behind it yet - so that a
later reviewer, a person or a model, can come back to it with the right question. A hint is not
a finding and carries no severity; it says where to look and what to ask.

`mcp-scanner inventory` writes the hints it can derive from the source tree under
`review_hints`. A pipeline can add hints derived from a scan report (findings in
`needs_review`, analysis that stopped early) in the same shape.

Each hint has:

| Field | Meaning |
|---|---|
| `code` | One of the codes below. New codes are added as new situations are met. |
| `file`, `line`, `capability` | Where it applies; `capability` is the tool, prompt or resource name when there is one. |
| `observed` | What the scanner saw, in one sentence. |
| `undecided` | What static analysis could not decide. |
| `question` | The question a reviewer should answer. |
| `how_to_check` | A concrete way to answer it: code to read, a runtime test to run. |
| `strength` | `suspicion` (worth a look, nothing seen yet) or `lead` (a path or a pattern points at it). |
| `related` | Finding ids the hint is about, when it came from a scan report. |
| `origin` | Set by a pipeline that merges hints: `inventory` or `scan_report`. |

## Codes

### Registration and coverage

`dynamic_registration` - a capability whose name, description or handler is computed at run time:
a loop over a table, a low-level `tools/list` handler, a proxy that forwards another server's
tools. The scanner analyzed nothing it could not see. Ask: what does this register at run time,
and what do those tools do? Check: read the data or the upstream server the list comes from; list
tools against a running instance.

`registration_not_recognized` - the tree imports an MCP SDK but no registration was found, so no
tool was analyzed. Ask: how does this server register its tools? Check: find the registration
code and report its form so the scanner can learn it.

`registration_skipped` - calls named like a registration that were not counted: the receiver is
an imported third-party module (`boto3.resource("s3")`), or every argument is a string literal, so
there is no handler or content (`api.root.add_resource("v1")` in an infrastructure library). The
reason comes from the call, not from the receiver's type. Ask: is any of them a real registration?
Check: read the receiver's type; list capabilities against a running instance.

`handler_not_found` - a registration whose handler was not found in the tree: it comes from a
dependency, is built at run time, or the call is not a registration at all (a cloud SDK's
`session.resource("dynamodb")` on an object the scanner cannot type). Nothing behind it was
analyzed. Ask: is it a real registration, and what does its handler do? Check: read the call and
the receiver's type.

`hand_rolled_protocol` - no registration was found, but source files spell MCP methods such as
`"tools/call"`: a JSON-RPC dispatcher written without an SDK. No tool was analyzed. Ask: which
tools does it serve, and what do they reach? Check: read the dispatch and follow each tool name.

`unsupported_language_files` - source files in a language the scanner does not parse (C#, Kotlin,
Swift, Lua, shell). Server code there was not analyzed. Ask: does any MCP handler live there?
Check: read those files.

`analysis_incomplete` - an analyzer stopped early: a time budget, a per-function seed limit, too
deeply nested calls, ambiguous calls it could not follow. Findings may be missing, and results can
differ between runs. Ask: are there paths the scanner did not finish? Check: rescan alone with a
larger budget; read the handlers that reach the limits.

`minified_code` - minified or bundled files were parsed. Paths through them are unreliable and
hard to read. Ask: is the bundled code part of the server, and is any finding in it real? Check:
map the bundle to its source.

### Data flow the scanner could not finish

`unresolved_call_on_path` - a path continues only because the scanner assumed a call it could
not follow (a library function, an API response, a parser) passes its argument on. Ask: does the
value really reach the sink unchanged? Check: read the call's documentation or source.

`helper_built_value` - a URL, path or query is built by a helper function whose return value the
scanner does not trace (`api.get(commentUrl(id))`), or a base and a path live in separate
variables. Ask: can the caller's part change the host, escape the directory, or break out of the
query? Check: read the helper.

`project_validator` - a value passes through the project's own validation function before a
sensitive call. The scanner does not verify it. Ask: does it reject every dangerous input -
`..`, absolute paths, symlinks, quotes, schemes other than https? Check: read it; test it with
those inputs.

`external_precheck` - the same caller value is sent to an external API before it reaches a
sensitive local call (an ACK cluster id used in an API call, then in a file name). Exploitability
depends on what the API accepts. Ask: does the API reject the dangerous form before the local
call runs? Check: read the call order; test the API with a traversal value.

`prefix_plus_whole_value` - a fixed prefix is put in front of the caller's whole value
(`EXPLAIN ANALYZE {sql}`, an optimizer hint before a query). It is read as an injection, but may be
the tool's stated purpose. Ask: does the tool mean to run the caller's statement? Check: read the
tool's description and the other tools of the server.

### Inputs whose meaning depends on the SDK or the deployment

`resource_template_parameter` - a resource URI template parameter (`docs://{name}`) reaches file or
network access. Whether it can carry `/`, `..` or a decoded `%2F` depends on the SDK's template
matching. Ask: can a client reach files or hosts outside the intended set through this URI?
Check: read the SDK's URI matcher; try `..`, `%2F` and `%252F` against a running instance.

`annotations_not_visible` - in a source scan, tool annotations (`readOnlyHint`, `destructiveHint`,
`openWorldHint`) and input schemas may be set where the scanner cannot see them. Ask: does a tool
that writes, deletes or runs commands declare itself destructive? Check: list tools against a
running instance.

### Behavior a reviewer should confirm

`dangerous_capability_restrictions` - a tool does a dangerous thing by design (runs commands or
queries, reads or writes paths, fetches URLs the caller names). The scanner recognizes root
checks but not host allowlists, path allowlists kept in configuration, or confirmation in the
client. Ask: what stops an agent steered by prompt injection from misusing it? Check: read the
configuration and the handler; look for an allowlist or an approval step.

`untrusted_content_to_model` - a tool returns content it fetched or read (a web page, an email, a
file, an issue) to the model. That content can carry indirect prompt injection. Ask: can an
outsider write what this tool returns? Check: read where the content comes from.

`credentials_and_network` - a handler reads credential-like environment variables and makes
network calls. Ask: are the credentials sent only to the service they belong to? Check: follow the
variables to the requests.

`outbound_hosts` - the hosts a handler can contact, from literal URLs. Ask: are they all the
vendor's own service? Is any of them telemetry or a third party? Check: compare them with the
documentation.

`duplicate_capability_name` - two registrations share a name. A later one may shadow an earlier
one, or a tool may impersonate another. Ask: which one does a client see? Check: list tools
against a running instance.

`non_english_description` - a description is mostly not in English. The behavioral and
prompt-defense vocabularies are English, so their checks are weak for it. Ask: does the
description promise, deny or instruct anything? Check: read or translate it.

### Derived from a scan report

These codes are not written by `inventory`; a pipeline derives them from a scan report, one hint
per group of `needs_review` findings with the same reason, and lists the finding ids in `related`.
`project_validator`, `unresolved_call_on_path` and `analysis_incomplete` above are derived the same
way from their triage reasons and coverage limits.

`reachability_unknown` - no MCP handler was resolved, so whether a tool call reaches the code is
unknown. Ask: can a tool call reach it, and with what input? Check: find how the server registers
its tools.

`external_content_flow` - file contents or an HTTP response reach a sink. Ask: who controls that
content - an outsider (a fetched page, a cloned repository) or the operator (a local config file)?

`name_based_match` - a sink was matched by method name alone (`jobs.execute` read as SQL). Ask: is
the receiver really a database handle? Check: read its type.

`heuristic_text_match` - a high-severity text pattern matched. Ask: is it an instruction to the
model or ordinary prose? Check: read the text in context.

`dependencies_not_checked` - lockfiles in an unsupported format, ranges with no lockfile, or
vendored dependencies were not checked for known vulnerabilities. Check: run the ecosystem's audit
tool on the resolved tree.

`needs_review_other` - a `needs_review` finding whose reason has no code yet. Read the finding's
`triage_reason`; add a code when the same reason recurs.

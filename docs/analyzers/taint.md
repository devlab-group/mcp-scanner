# Taint analyzer

`taint` traces untrusted values to dangerous calls on source and package
targets. Each hop becomes a `model.FlowStep`, including cross-file calls into
resolved repository functions. It uses the source graph and coverage described
in [source and behavioral analysis](source-and-behavioral.md).

## Sources and sinks

Sources include:

- tool, prompt, and resource handler parameters;
- environment variables;
- file contents;
- HTTP response bodies.

Sink categories include command and argument injection, path traversal, SSRF,
raw sockets, SQL injection, dynamic code loading, unsafe deserialization, and
server-side template injection.

SQL sinks inspect the query argument, not later bound values. Template sinks
inspect the configured argument for each recognized API; for example,
`template.New` inspects its name argument. A parameterized SQL query
is allowed, while concatenating untrusted text into the query is reported.

The language-specific catalogs cover selected process, filesystem, HTTP, SQL,
template, and deserialization APIs across Go, Python, JavaScript, TypeScript,
Java, and Rust. Coverage differs by language and includes some third-party APIs,
such as `execa`.

## Source class, reachability and severity

The catalogue severity of a sink is how bad it is when an attacker controls the value. In the
MCP threat model the attacker is the client side: a model steered by prompt injection fills
tool arguments. Each finding records `source_class` and `reachability`, and severity and
triage follow from them:

| Path starts from | Reachable from an MCP handler | Severity | Triage |
|---|---|---|---|
| tool, prompt or resource argument | yes, by construction | catalogue | `potential` |
| HTTP response or file contents | yes, possible or unknown | catalogue | `needs_review` when HIGH or above |
| environment variable | yes, possible or unknown | at most LOW | `context` |
| any source | no | INFO | `context` |

Content from a URL or a file may be attacker-written, such as a fetched page or a cloned
repository, or may be the server's own configuration. The path alone cannot tell which, so the
finding keeps its severity and a person decides. "Not reachable" is claimed only when the start
of the path is not reached even if every unresolved call is read as a call to any function of
that name; module-level code counts as possibly reachable. File names play no part: a file
named like a test is analyzed like any other.

A path from MCP input that only continues because the analyzer assumed an unresolved call - a
library function, an API response, a parser - passes its argument on goes to `needs_review`:
the step is in the evidence path with kind `unknown`. Parameters the SDK injects are not MCP
input: FastMCP's `Context`, Go's `context.Context` and the TypeScript SDK's
`RequestHandlerExtra` (or an untyped `extra` after the first parameter). The type decides, not
the name, so a `context: str` tool argument is still traced.

A path that passes through the project's own validation function - an in-repo function named
like `validate*`, `sanitize*`, `check*`, `ensure*` or `verify*` whose body can raise or throw -
goes to `needs_review`, whether the function is called as a guard statement
(`validate_table_name(t)`) or returns the checked value (`safe = validate_file_path(p)`). Taint
is not cleared: the scanner does not verify the check, and a broken one must not hide the
finding.

## Dangerous capabilities

A path from MCP input becomes a dangerous capability (`finding_kind: dangerous_capability`)
rather than a vulnerability when all of these hold:

- the tool's name or description declares what the sink does: running a command (command,
  shell, cmd, "runs a command"), executing code, file access, network access, or running a query
  (sql, query, database, table);
- the argument reaches the sink as a whole value: no concatenation, interpolation, format call,
  or path join with a base directory on the way (a join under a base is a boundary the tool
  meant to keep, so escaping it is a vulnerability);
- the description promises no boundary (under, within, inside, only, allowed, workspace,
  sandbox, ...) that the code would have to enforce;
- no step of the path passes through a call the analyzer could not follow.

The rule id, sink and severity stay; the title names the capability. Severity drops one step
when the handler can reach an elicitation or confirmation call. A root-directory check would
have cleared a `file_access` finding, so one that remains has none. Host allowlists are not
recognized yet, so a `network_request` finding may have one the scanner does not see.

## Propagation

A helper reached by several paths is walked once per distinct seed shape, where the shape is the
set of tainted parameters together with the class of the source each one came from. Of several
paths to the same sink the finding keeps the most severe one after classification, so a path
from file contents that needs review is not hidden by an environment-variable path to the same
call.

Every resolved handler parameter is seeded, including destructured and compact
Go declarations and inline handlers. Taint propagates through assignments,
calls, receivers, indexing, member access, recognized loop and callback
bindings. A zero-argument handler is valid; unresolved parameter names create a
coverage gap. A call result inherits taint from a tainted argument or receiver;
helper return values are not analyzed directly. When tainted arguments enter a
resolved repository function, all matching parameters form one seed and tracing
continues. Each distinct seed shape is traced, up to eight per symbol.

Python and JavaScript/TypeScript augmented assignments preserve existing taint.
Go augmented assignments use the plain assignment path and can clear it, so a
flow such as `tainted += "literal"` may be missed and produce `SAFE`.

An unresolved call conservatively propagates taint to its result with reduced
confidence and adds an unresolved step to the evidence path. This favors a
visible weak finding over silently dropping the flow.

Identifier matching uses whole words in expression text. Literal contents are
masked so a column named like a variable does not create a false flow. String
interpolation remains visible. This approach is lightweight but has no full
scope, alias, or path-sensitive analysis.

## Process execution

Shell APIs treat taint in their command string as command injection. Argv APIs
are classified more precisely:

1. Tainted program name: `command_injection`, `HIGH`.
2. Known shell with `-c`, `/c`, `-command`, or equivalent: `HIGH`.
3. Python `shell=True` or Node `shell: true`: `HIGH`.
4. Literal non-shell program with a later tainted argument:
   `argument_injection`, `MEDIUM`.
5. Unknown program: command injection at reduced confidence.

The classifier recognizes shell paths, Windows `.exe` names, clustered flags
such as `-lc`, and `env NAME=value sh -c ...`. A literal `--` before a tainted
argv value suppresses both the argument-injection and unknown-program cases
because later values cannot be parsed as options.

## Receivers and method matching
A bare-name sink (`fetch`, `exec`, `spawn`) called by that bare name yields to a function the
project defines under the same name: the call is followed into that function instead. `exec` on
a database-like receiver (`this.sql.exec(query, ...bindings)`, `db.exec(sql)`) is a SQL call
checked at its query argument, not a process launch. Rust's `self`, `&self` and `&mut self` are
the tool struct, not client input.

asyncpg's `fetch`, `fetchrow` and `fetchval` on a database-like receiver are SQL calls, not the
HTTP `fetch`. SQL methods matched by name alone (`execute`, `query`, `Exec`, ...) count as SQL only when the
receiver is named like a database handle (`cursor`, `conn`, `db`, `session`, `client`, `engine`,
...) or the checked argument contains SQL text, so `jobs_tool.execute(params)` is not a query.
Call resolution is by method name, so an in-repo class with an `execute` method used to make
every `cursor.execute(...)` resolve to it and hide real SQL injection; a database-like receiver
now keeps the SQL check while the in-repo method is still followed.

Taint can flow through a receiver, as in `Path(user).read_text()` or chained
builder calls. Module-qualified sinks and generic method names use separate
matching rules. Generic methods are ignored when they resolve to an in-repo
helper.

A bare `get` or `post` method counts as an SSRF sink when its receiver is
recognized as an HTTP client from `axios`, `httpx`, `aiohttp`, or `requests`.
The scanner recognizes the module itself (`httpx.get`), a client constructed
at the call site (`httpx.AsyncClient().get`), and clients assigned in the same
file. Assignments include `client = httpx.AsyncClient()`, `async with
aiohttp.ClientSession() as session`, `const api = axios.create()`, and class
fields. Importing an HTTP client alone does not make a dict, `Map`, or
response object's `get` method a sink.

## SSRF
A URL that starts with literal text of the form `/word` (`` `/repositories/${ws}/pulls` ``,
`f"/v1/product/{id}/"`) is a relative path resolved against the client's configured base, so it
cannot name another host. A bare `/` followed by an interpolation still counts: `"/" +
"/evil.example"` is a protocol-relative URL.

A URL that starts with an expression the MCP client does not control, followed by literal text
beginning with `/`, `?` or `#`, has a fixed host: `f"{ENDPOINT}/tasks/{task_id}"`, `` `${base}/v1/${id}` ``,
`base + "/items/" + id`, `fmt.Sprintf("%s/items/%s", base, id)`. Text after that `/` is in the
URL's path and cannot move the request to another host. This assumes the base holds a scheme and
host, as a configured endpoint does.

The analyzer checks tainted URL arguments for SSRF and clears the taint when
it can identify a fixed destination host. The URL is the first positional
argument or Python's `url=` keyword, the second argument of Go's `http.NewRequest`, or the third
argument of `http.NewRequestWithContext`. Taint in headers, a request body, or
the client receiver does not count. Query parameters and paths after a fixed
host do not give control over the host.

A fixed URL prefix clears SSRF taint when it supplies the scheme and ends the
host with `/`, `?`, or `#` before computed text begins. Recognized forms include
`f"https://api.example.com/items/{item}"`, `"https://api.example.com/" + item`,
`"https://api.example.com/{}".format(item)`, and Go's
`fmt.Sprintf("https://api.example.com/%s", item)`. The analyzer still reports
`"https://api.example.com" + item`: appending `@evil.example` or `.evil.example`
can change the host. A Python module constant can supply the fixed prefix,
and assigning a URL with a fixed host to a variable preserves its SSRF
clearance.

Receiver-blind method matching still creates limits. Callback-style `sqlite3`
methods such as `db.get` and `db.run` are deliberately excluded because the
same names are common in unrelated APIs; prepared-statement forms remain
covered.

## Sanitizers

Strong sanitizers clear taint for the relevant sink category. Examples include
basename extraction for paths and `shlex.quote` for one shell token.

Weak sanitizers keep the flow but lower confidence and add a sanitizer step.
Examples include path cleaning without containment, string replacement, and
URL parsing without destination validation.

Sanitization is category-specific. A path sanitizer does not clear the same
value for SQL or command execution. Property forms such as
`Path(value).name` and destructured imports such as `basename(value)` are also
recognized.

## Path containment guards

The analyzer clears only `path_traversal`, and only for a plain identifier in a
resolve-then-contain pattern with all these parts:

- the escape branch exits unconditionally;
- the condition tests the tainted path with a known containment predicate;
- the value was normalized before the check, except for Go's `filepath.Rel`
  idiom;
- character-prefix checks include a path separator boundary;
- the root is not empty or `/`;
- the containment predicate actually decides the branch, rather than being
  hidden behind an unrelated `&&` condition.

The guard cannot have an `else` or `elif`; its escape branch must end in
`return`, `raise`, or `throw`. Checks moved into helper functions are not
recognized, and only a literal root is checked for the unsafe empty or `/`
case.

Supported forms include `is_relative_to`, component-aware `startsWith` or
`starts_with`, anchored JavaScript/TypeScript prefix checks, Go
`strings.HasPrefix` checks, and `filepath.Rel` followed by a `..` test.

These rules prevent weak checks from hiding traversal. `filepath.Join`,
`path.join`, and `path.resolve` normalize. The pathlib `/` operator clears a
prior normalization guarantee; `os.path.join` does not, which is a known false
negative. Comparing `/srv/notes-secret` with the prefix `/srv/notes`, or
guarding only when an unrelated flag is true, also leaves the flow tainted.

## Coverage and limits

A capability counts as analyzed only when its handler and taint sources can be
resolved. Unresolved handlers remain uncovered even if another capability was
analyzed. File walk, parse, and truncation gaps from the shared source pipeline
are folded into the result.

Known limitations include:

- no full type inference, alias analysis, scope tracking, or path sensitivity;
- interprocedural tracing stops after eight nested calls and records a limit,
  so a deeper flow downgrades the scan instead of passing;
- ambiguous callees are not followed, and a same-name in-repository function
  can hide a receiver-blind method sink;
- at most eight distinct tainted-parameter combinations are traced per symbol;
- values selected by a tainted collection key are treated as untainted;
- appending to a field or nested collection does not taint that collection;
- argv stored in a variable cannot be inspected element by element;
- recognized decoders undo a clearance because they can reintroduce path
  syntax; unrecognized decoders, such as Java's `URLDecoder.decode`, may leave
  the clearance in place;
- incomplete catalogs for uncommon or receiver-ambiguous APIs;
- clients supplied by another file, a parameter, a factory function, or a
  lifespan context are not recognized as receivers for `get` and `post` sinks;
- recognizing a fixed host requires a literal or a Python module constant at
  the call site or in the assignment that builds the URL;
- fixed sanitizer names and the limited containment shapes above;
- an in-repository helper named `basename` may be mistaken for a path sanitizer;
- conservative propagation through unknown calls;
- no macro expansion, reflection, or runtime dispatch analysis;
- possible false positives from same-named variables in nested scopes.

Reusing a source graph without its original walk coverage makes the result
`PARTIAL`. Files reopened for taint parsing remain confined to the scan root
through `os.Root` and use the same size and parse-time limits as source parsing.

Vulnerable, fixed, benign, and holdout fixtures under `testdata/source/taint`
and `evals/` cover cross-file flows, process API distinctions, sanitizers,
containment checks, destructuring, callbacks, unknown calls, and most sink
categories. Server-side template injection has no dedicated fixture.

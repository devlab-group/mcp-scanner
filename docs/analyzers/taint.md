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

## Propagation

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

Taint can flow through a receiver, as in `Path(user).read_text()` or chained
builder calls. Module-qualified sinks and generic method names use separate
matching rules. Generic methods are ignored when they resolve to an in-repo
helper. The receiver-blind `get` and `post` SSRF sinks also require the file to
import `axios`, `httpx`, `aiohttp`, or `requests`.

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
- incomplete catalogs for uncommon or receiver-ambiguous APIs, including the
  file-level HTTP import gate for `get` and `post`;
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

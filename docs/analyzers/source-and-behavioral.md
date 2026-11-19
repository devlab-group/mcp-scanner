# Source and behavioral analysis

The `source` analyzer discovers MCP registrations. The `behavioral` analyzer
compares each capability's description with calls reachable from its handler.
The [taint analyzer](taint.md) uses the same source graph.

## Pipeline

| Package | Role |
|---|---|
| `internal/source/inventory` | Walk files within the scan root and record limits or skips. |
| `internal/source/language` | Select a tree-sitter grammar and queries. |
| `internal/source/parser` | Extract symbols, imports, calls, and return values. |
| `internal/source/graph` | Hold the repository-wide symbol and call graph. |
| `internal/source/registration` | Find tool, prompt, and resource registrations. |
| `internal/source` | Build and publish the graph and walk coverage. |

Source, taint, and behavioral analyzers share the graph through the scan's
artifact store. Each can build it when called independently. Walk coverage is
shared with the graph so reused data cannot hide skipped or failed files.

## Languages

| Language | Extensions |
|---|---|
| Go | `.go` |
| Python | `.py`, `.pyi`, `.pyw` |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx` |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` |
| Java | `.java` |
| Rust | `.rs` |

The parser extracts functions, methods, classes where applicable, decorators or
annotations, calls, imports, parameters, and simple literal values. Call
resolution is name-based rather than type-based. A unique candidate resolves,
and a same-file definition breaks ties. Other ambiguous, reflective, or
computed calls remain unresolved.

Source files in known unsupported languages are counted as a coverage gap.
This includes C#, F#, Kotlin, Scala, Ruby, PHP, Swift, Objective-C, Dart,
Elixir, C/C++, Lua, Perl, and common shell or batch scripts. Executable or
shebang-prefixed files without an extension are treated as scripts. Ordinary
non-source files are ignored.

## Registration discovery

The scanner recognizes these forms:

- direct SDK calls such as `AddTool`, `registerTool`, and prompt/resource
  equivalents;
- Python, Java, and Rust decorators or annotations, including a decorator applied by a plain
  call, `mcp.tool()(fn)` or `mcp.tool(name="x", description="...")(fn)`;
- the Go SDK's `server.AddTools(mcp.NewServerTool(name, description, handler, ...))`;
- wrapper helpers that forward names and handlers to an SDK;
- registration inside tables and loops, recorded as one unresolved capability
  per loop site;
- factory calls and Go-style functional options;
- low-level list and dispatch request handlers;
- cross-file definitions and aliased imports.

Literal names and descriptions are preserved. Supported string forms include
plain and triple-quoted strings, Python implicit concatenation in parentheses,
Java text blocks, and Rust raw strings. The scanner also resolves string
constants within the same file:

- Python: a module-level `NAME = "..."` assignment with no other binding of
  that name anywhere in the file. A star import or a reference to `globals`,
  `vars`, `setattr`, `exec`, `eval`, `__dict__` or `__import__` leaves constants
  unresolved.
- Java: a `static final String` field or an interface string constant,
  initialized with a literal or a `+` concatenation of literals. No other
  field in the file may declare the same name.
- Rust: a `const` or `static` of type `&str`, with no other `const` or `static`
  in the file declaring the same name.

Constants are not resolved across files.

Decorator and annotation arguments supply the name and description. If a name
argument is absent, empty or `None`, the scanner uses the function's name. The
same rule applies to a description argument and the function's docstring. An
unresolved argument, such as a conditional, call or f-string, leaves that field
unresolved rather than using the fallback.

For Python `tool` and `prompt` decorators, the first positional argument is
the name and the third is the description. For `resource`, the first is the
URI. A function without a docstring has a known empty description; a comment
does not count as a docstring. For Java, LangChain4j's `@Tool("...")` value is
the description; an array of strings supplies its lines.

Rust and Java tools without a description argument remain unresolved. The
scanner does not read rmcp's doc comment fallback or Spring AI's description
derived from the method name.

An unresolved value still counts as a discovered capability and creates a
coverage gap.

Finding zero registrations is also a coverage gap. It may mean the directory
is not an MCP server or that the scanner does not understand its registration
form; neither supports a clean verdict.

Discovery does not resolve reflection, generated registrations, or JavaScript
and TypeScript decorators. These may be missed entirely; if another
registration is found, the omission can still produce `SAFE`. A target path
outside the configured scan root, or a tree with no candidate source files,
returns `ERROR`.

For source-only scans, `source.Synthesize` converts discovered capabilities to
a snapshot so prompt defense, readiness, YARA, and model-assisted analyzers can
inspect declared text. The snapshot uses transport kind `source`. Unresolved
fields remain visible in synthesis coverage.

## Behavioral comparison

`behavioral` uses fixed keyword catalogs, not a model. It compares descriptions
with calls reachable from each handler in four categories:

- network access;
- filesystem access;
- process execution;
- credential access.

Credential access requires a sensitive path or a credential-like environment
variable name. Generic reads such as `DEBUG` or `PORT` do not count.

An unresolved description is a coverage gap and is not judged as an empty
description. This avoids accusing a handler of undeclared behavior when its
real description could not be read.

The strongest finding is credential access combined with network access when
the description does not declare both
(`behavioral.credential_exfiltration_mismatch`, `CRITICAL`). It suppresses the
weaker network and credential findings for the same capability.

Negated claims are handled separately. A description such as "never makes a
network request" contradicts observed network behavior instead of declaring
it. Contradictions produce stronger findings than silence, using a bounded
word-window heuristic.

Behavioral findings use `STATIC` evidence. Reachability proves that calls are
available from the handler, not that a particular value flows between them.
Taint analysis handles value flow.

| Rule | Severity | Condition |
|---|---|---|
| `behavioral.credential_exfiltration_mismatch` | `CRITICAL` | Credential and network calls are reachable, but the description does not declare both. |
| `behavioral.contradicted_network` | `HIGH` | Reachable network use contradicts the description. |
| `behavioral.undeclared_network` | `HIGH` | Reachable network use conflicts with a local-only claim. |
| `behavioral.contradicted_credential_access` | `HIGH` | Reachable credential access contradicts the description. |
| `behavioral.undeclared_credential_access` | `MEDIUM` | Reachable credential access is not declared. |
| `behavioral.contradicted_process_execution` | `MEDIUM`, or `HIGH` with undeclared network or credential access | Reachable process execution contradicts the description. |
| `behavioral.undeclared_process_execution` | `LOW`, or `HIGH` with undeclared network or credential access | Reachable process execution is not declared. |
| `behavioral.contradicted_filesystem_access` | `MEDIUM` | Reachable filesystem access contradicts the description. |
| `behavioral.undeclared_filesystem_access` | `LOW` | Reachable filesystem access conflicts with a local-only claim. |

The source analyzer also emits `source.capability_name_unresolved` (`LOW`) when
a registration name is computed at runtime, and
`source.capability_no_description` (`LOW`) when neither the registration nor
its handler provides a statically known description.

## Limits

Known blind spots include:

- dynamic dispatch, reflection, generated code, macros, and metaprogramming;
- type-dependent call resolution and alias analysis;
- runtime-built registration collections;
- project-specific sanitizers not recognized by taint rules;
- callback-style `sqlite3` methods whose generic names would create excessive
  false positives.

The source inventory treats the scan root as a hard boundary. It does not
follow escaping symlinks and reads each canonical directory once. It enforces
limits on file size, total bytes, file count, directory depth, and walk time.
Reaching one of these limits creates a coverage gap. Refused symlinks count
as skips with reasons. A refused link also records a limit if it points to a
directory or has a source extension or no extension. When its target cannot
be examined, the link's extension determines whether it could hide source.
These limits create gaps because the server may load source the scanner did
not read. A link with a non-source extension to a non-directory target, or a
second path to a directory already walked, does not create a gap.

Oversized files are parsed up to the byte cap. Parsing and extraction share a
5 second deadline per file. Syntax trees deeper than 32,768 levels are rejected
before queries run because tree-sitter's 16-bit query depth can silently lose
matches beyond 65,535 levels. Call text that cannot share the source buffer is
capped at four times the file size plus 16 KiB. Exceeding the time, depth or
text budget creates a coverage gap. Taint reparsing uses the same byte, depth
and time limits.

The scanner never excludes a file because its name or contents claim it is
generated. It also scans arbitrary dot-directories and build directories such
as `dist`, because published packages often contain only built output.

The fixed cache/VCS skip list is `.git`, `__pycache__`, `.mypy_cache`, and
`.pytest_cache`; source found inside one creates a gap. The dependency skip list
is `vendor`, `node_modules`, `.venv`, and `venv`; these directories always create
a reported gap. File-count and total-size limits continue counting the remaining
tree so the report shows how much was omitted.

A reasoned capability skip does not create a gap unless every discovered
capability was skipped. The zero-analyzed-capability floor then blocks `SAFE`.

File coverage accounts for skips with recorded reasons. Skips that could hide
source also record a limit, which creates a coverage gap.

Source and package targets use the same pipeline. Package extraction supplies
the scan root directly, while source targets resolve the requested path within
the configured root.

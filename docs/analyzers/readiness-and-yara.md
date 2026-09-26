# Readiness and YARA

`readiness`, `yara`, and [promptdefense](promptdefense.md) inspect
the discovered snapshot. They do not contact the target or read its filesystem.

## Readiness

`readiness` reports missing safety signals. Most findings are `INFO` or `LOW`;
they are review prompts, not proof of an attack.

| Rule | Severity | Meaning |
|---|---|---|
| `readiness.no-instructions` | `INFO` | The server declares no instructions. |
| `readiness.tool-missing-description` | `LOW` | A tool has no description. |
| `readiness.tool-missing-schema` | `LOW` | A tool has no input schema. |
| `readiness.destructive-not-annotated` | `MEDIUM` | Destructive wording appears without `destructiveHint: true`. |
| `readiness.no-auth-declared` | `INFO` | Discovery found no authentication signal. This does not prove the server is open. |
| `readiness.resource-unconstrained-uri` | `LOW` | A resource URI contains `..` or has no literal path prefix. |

The fixture corpus is under `testdata/rules/readiness/cases/`. Run it with:

```sh
go test ./internal/analyzers/readiness/... -run TestCorpus -v
```

`readiness` does not resolve resource URIs or confirm authentication. The
`auth` analyzer performs active authentication checks.

## YARA

`yara` matches signatures against tool and prompt descriptions, prompt text,
resource contents, and server instructions. It requires libyara and the
`yara` build tag:

```sh
make build-yara
```

The default build registers an `UNAVAILABLE` stub so missing YARA support is
visible. A tagged build loads `*.yar` and `*.yara` files in this order:

1. Explicit `rules.yara_dir`. A missing or empty configured directory fails and
   the directory replaces, rather than merges with, the embedded rules.
2. `rules/yara` beside the binary, which also replaces the embedded rules.
3. Rules embedded from `rulesdata/`.

Rules are never loaded from the working directory, so a scanned tree cannot
supply its own signatures.

The repository ships two files:

- `prompt_injection.yar` detects instruction overrides and fake system turns.
- `credential_exfiltration.yar` detects credential requests and URL-based
  exfiltration phrases.

The enabled analyzer compiles embedded rules at runtime and returns `ERROR` for
invalid YARA syntax. Untagged tests check rule structure and synchronization
between rule copies; they do not compile or match rules through libyara. Full
fixture matching and some failure paths remain unverified, so treat YARA as a
supporting signal.

## Coverage

Readiness counts every discovered capability as analyzed. It checks tool
descriptions and schemas, resource URIs, and server instructions; it does not
scan prompt or resource descriptions. On source snapshots, only the
missing-tool-description check runs.

YARA scans tool and prompt descriptions, prompt text, resource contents, and
server instructions. It does not scan names or resource descriptions. A tool or
prompt with no scannable text is skipped; missing resource content creates a
coverage limit because the body was not inspected. Use `--read-resources` and
`--get-prompts` on live targets; static and source targets have no session to
fetch from, so those flags are rejected.

Snapshot truncation, failed pagination, and file-walk limits flow into analyzer
coverage. On source and package targets, the analyzers inherit the source
walk's failed and skipped file counts. Prompt defense also folds unresolved
source declarations into its coverage. Known limitation: a recorded file-skip
reason can account for unrelated skipped files, so partial discovery can still
produce `COMPLETED/SAFE`.

# Prompt defense analyzer

`promptdefense` scans text that an MCP server exposes to a model: names,
descriptions, prompt bodies, resource contents, server instructions, tool input
and output schemas, and all string leaves in annotations and `_meta`. It works
on remote, stdio, static, source, and package snapshots without contacting the
target.

## Rule loading

Rules are loaded in this order:

1. `rules.prompt_defense_dir` when configured. Missing or empty directories fail.
2. `rules/prompt-defense` beside the executable.
3. Rules embedded in the binary.

Disk rules merge over embedded rules by id, so a custom directory can replace
one built-in rule and add others. Disk rules are cached for 30 seconds;
embedded rules are compiled once per process. Rules are never loaded from the
working directory, so a scanned tree cannot supply the rules used to judge it.
The result warns when it uses a non-default rule set.

## Matching

Pattern rules use regular expressions. Structural rules inspect facts such as
hidden characters, decodable blobs, or conflicting fields.

For most rules, a nearby defensive phrase or negation lowers severity by one
step and reduces confidence. Quoting alone lowers confidence; quoting plus a
qualifier lowers severity to `LOW`. For premise rules such as credential
harvesting and exfiltration, missing required context means no match. The
qualifier window stays within the match's sentence. Prefix qualifiers such as
"for example" count only before the match, so an attacker cannot append one to
neutralize earlier text.

Each rule has vulnerable, fixed, and benign fixtures under
`testdata/rules/promptdefense/`; `regression/` is shared by all rules. Run them
with:

```sh
go test ./internal/analyzers/promptdefense/... -run TestCorpus -v
```

## Scanned fields and limits

Schema scanning visits every string leaf through nested objects, arrays,
`$defs`, and `definitions`. Annotation and `_meta` scanning also visits every
string leaf. A shared per-tool budget covers input schema, output schema,
annotations, and `_meta`: maximum depth 8 and maximum 200 text units. Reaching
either limit creates a coverage gap.

Invisible Unicode tag runs are decoded and scanned again, allowing the analyzer
to classify the hidden message as well as report the encoding.

## Rules

### `promptdefense.instruction-override`

Finds requests to ignore earlier instructions or assume an unrestricted
persona. Defensive descriptions such as "detects attempts to ignore previous
instructions" are downgraded. Literal, English phrase matching can miss
paraphrases and translations.

### `promptdefense.fake-turn`

Finds line-leading `system:` or `assistant:` turns. It excludes the noisier
`user:` label and downgrades common documentation forms such as system
requirements.

### `promptdefense.hidden-chars`

Finds zero-width characters, bidi overrides and isolates, soft hyphens,
variation selectors, Unicode tags, and related invisible formatting. A BOM at
the start of a field is allowed; a mid-text BOM is not. Ordinary left-to-right
and right-to-left marks are excluded.

### `promptdefense.confusable-script`

Finds a single word containing letters from more than one of the Latin,
Cyrillic, and Greek scripts. Words written entirely in one script do not match;
other script families are not covered.

### `promptdefense.html-comment`

Finds `<!-- ... -->` content that a Markdown or HTML renderer may hide while a
model still receives it.

### `promptdefense.base64-blob`

Finds 40 or more base64 characters that decode to at least 16 bytes with useful
entropy. All-lowercase or all-uppercase hexadecimal strings are excluded.
Legitimate embedded binary data can still match; URL-safe base64 is not covered.

### `promptdefense.tool-poisoning-call-other-tool`

Finds instructions to call another tool or act without telling the user.
Defensive scanner descriptions and privacy promises are downgraded. Indirect or
unusual phrasing can evade the fixed vocabulary.

### `promptdefense.tool-poisoning-unrelated-file-access`

Finds instructions to read or hand over sensitive files such as SSH keys,
cloud credentials, package-manager credentials, browser data, and MCP client
configuration. Audit and backup descriptions can be legitimate and may need
review. The rule covers a fixed path list.

### `promptdefense.tool-poisoning-pseudo-tag`

Finds wrappers such as `<IMPORTANT>`, `<SYSTEM>`, `<secret>`, and bracketed
system notes. It is `MEDIUM` by itself and often accompanies a more specific
poisoning finding. Legitimate placeholder syntax can match.

### `promptdefense.credential-harvesting`

Finds named credential types near verbs such as send, paste, share, or reveal.
Password-manager and local-storage language is downgraded. Support instructions
that legitimately ask a person for credentials can still match.

### `promptdefense.exfiltration`

Finds data-movement verbs near an HTTP URL or a host from a conservative TLD
list. A valid URL promotes evidence from `HEURISTIC` to `STATIC`.
Documentation language immediately before a URL lowers severity. Legitimate
webhook tools can match; non-URL channels such as DNS or synced files are not
covered.

### `promptdefense.oversized-description`

Finds descriptions over 1,500 characters, or over 500 characters for tools with
at most one parameter. Rule files can override both thresholds.

### `promptdefense.conflicting-metadata`

Finds `readOnlyHint: true` paired with language about deleting, writing,
executing, or changing state. Explicit denials lower severity. The rule does not
compare `idempotentHint` or `openWorldHint`.

## Coverage

Missing prompt or resource bodies remain coverage gaps on remote, stdio, and
static snapshots even when their names and descriptions were scanned. On source
and package targets, they are recorded as skips because no live session can
fetch them. Use `--get-prompts` and `--read-resources` on live targets. Snapshot
truncation, unresolved synthesized fields, and source walk limits are folded
into this analyzer's coverage. See [readiness and YARA](readiness-and-yara.md).

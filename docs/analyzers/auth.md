# Auth analyzer

`auth` tests authentication and session boundaries on remote targets. It skips
every other target kind. Every check, including metadata discovery, requires
`--active-probes safe` or higher. The only real tool call uses an
operator-selected, allowlisted identity tool.

## Test credentials

The scanner cannot mint tokens for the target's authorization server. Supply
tokens for specific negative cases through environment variables:

```yaml
analyzer_options:
  auth:
    tokens_env:
      valid: MCP_SCANNER_AUTH_TOKEN_VALID
      expired_token: MCP_SCANNER_AUTH_TOKEN_EXPIRED
      wrong_audience: MCP_SCANNER_AUTH_TOKEN_WRONG_AUDIENCE
      wrong_issuer: MCP_SCANNER_AUTH_TOKEN_WRONG_ISSUER
      insufficient_scope: MCP_SCANNER_AUTH_TOKEN_INSUFFICIENT_SCOPE
      excessive_scope: MCP_SCANNER_AUTH_TOKEN_EXCESSIVE_SCOPE
      user_b: MCP_SCANNER_AUTH_TOKEN_USER_B
    identity_tool: whoami
```

Literal `tokens` values override `tokens_env`, but make the config file a
credential. `mcp-scanner config` redacts them. A missing `valid` token falls
back to the target's configured `Authorization` header.

`identity_tool` should return the caller's identity. It can confirm a cross-user
session leak and enables the token-passthrough check. It requires
`--active-probes tool-calls` and must be allowlisted.

## Passive checks

The analyzer fetches RFC 9728 protected-resource metadata without credentials.
The guarded HTTP client enforces address policy and refuses cross-origin
redirects. Failures produce one generic warning. Details are logged only at
debug level.

| Rule | Severity | Meaning |
|---|---|---|
| `auth.plaintext_transport` | `MEDIUM` | Tokens or session ids travel without TLS. |
| `auth.resource_identifier_mismatch` | `MEDIUM` | Metadata identifies a different resource server. |
| `auth.authorization_server_cross_origin` | `LOW` | Authorization uses another origin. This is common and only needs review. |

## Credential matrix

Each active case opens a session and confirms it with `tools/list`. Outcomes
are:

- accepted: the session is usable;
- rejected: a typed session rejection or HTTP 400, 401, or 403;
- inconclusive: timeout, network failure, malformed response, 5xx, 429, or an
  unexplained 404.

An inconclusive outcome makes the analyzer `PARTIAL`. For a request carrying a
session id, a 404 counts as rejection only after a no-session control proved the
endpoint works.

| Case | Required input | Finding if accepted | Severity |
|---|---|---|---|
| `no_token` | none | `auth.no_auth_required` | `HIGH` with auth metadata, otherwise `LOW` |
| `valid_token` | valid token or configured header | control | none |
| `invalid_token` | built-in garbage token | `auth.invalid_token_accepted` | `CRITICAL` |
| `expired_token` | expired token | `auth.expired_token_accepted` | `HIGH` |
| `wrong_audience` | wrong-audience token | `auth.audience_not_validated` | `HIGH` |
| `wrong_issuer` | wrong-issuer token | `auth.issuer_not_validated` | `HIGH` |
| `insufficient_scope` | limited token | `auth.scope_not_enforced` | `MEDIUM` |
| `excessive_scope` | broad token | `auth.scope_enforcement_inverted` if this token is rejected after the limited token was accepted | `MEDIUM` |
| `session_user_a` | valid token | ownership control | none |
| `session_user_b` | second user's token | `auth.session_not_bound_to_user` | `HIGH`, or `CRITICAL` when identity is confirmed |
| `reused_session` | closed valid session | `auth.reused_session_accepted` | `MEDIUM` |
| `malformed_session_id` | valid token; an issued session id is not required if the valid-token control failed | `auth.malformed_session_id_accepted` | `MEDIUM` |
| `guessed_session_id` | valid token | `auth.guessable_session_id` | `HIGH` |

Session ids are considered suspicious when shorter than 16 characters or when
two ids share a fixed prefix and differ only by a small numeric suffix. This is
a counter heuristic, not a randomness test.

Sessions stay open until dependent cases finish, then close once at the end of
analysis. Close failures become warnings.

If the valid-token control fails, `session_user_a`, `session_user_b`,
`guessed_session_id`, and `reused_session` are skipped.
`malformed_session_id` can still run with a configured valid credential.
If the no-token case succeeds, `invalid_token` and `session_user_b` are skipped
because the endpoint has already shown that it accepts unauthenticated access.

Token evidence shows only `Bearer` and the authorization-header length; it does
not expose token characters. Session ids show their first six characters and
length; values of six characters or fewer are shown in full.

## Standalone checks

`auth.session_fixation` proposes a client-chosen session id during initialize.
Adoption produces a `HIGH`, `CONFIRMED` finding. A server that refuses the
handshake leaves the check skipped, not passed. The check is also skipped when
a stateless server or legacy SSE connection exposes no session id to compare.

`auth.token_passthrough` calls the configured identity tool with the valid test
credential and checks whether the response echoes it. An echo produces a `HIGH`,
`PROTOCOL` finding. A deliberate credential-relay tool can be a false positive.

## Status and coverage

Coverage includes metadata discovery and all matrix cases. It includes the two
standalone checks only when the credential matrix runs. Every omitted case
records a reason.

- `SKIPPED`: wrong target kind, probe level below `safe`, or nothing could be
  attempted.
- `PARTIAL`: active probing was unavailable or a probe was inconclusive.
- `COMPLETED`: every attempted probe was accepted or clearly rejected.

Missing operator-supplied tokens do not make the result `PARTIAL`; they are
documented limitations. Probes that need no special token must still run.

Fixtures under `testdata/auth` cover policy failures, metadata behavior, and
session lifecycle. `internal/analyzers/auth/sessionleak_test.go` verifies cleanup.

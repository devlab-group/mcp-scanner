package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/httpx"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// maxMetadataBytes bounds the protected-resource metadata document read
// from the scanned server
const maxMetadataBytes = 1 << 20 // 1 MiB

// passive reads what the scanner already knows (TLS, response headers from
// the discovery snapshot) and, since that alone rarely says whether auth is
// actually required, makes one additional GET for the OAuth
// protected-resource metadata a compliant server publishes at a well-known
// path. It never sends any credential.
func (a *Analyzer) passive(ctx context.Context, st *state) []model.Finding {
	if st.ac.Snapshot != nil {
		st.tlsUsed = st.ac.Snapshot.Transport.TLS
	} else {
		st.tlsUsed = strings.HasPrefix(strings.ToLower(st.target.URL), "https://")
	}

	metaURL := wellKnownURL(st.target.URL)
	meta, err := a.fetchProtectedResourceMetadata(ctx, a.metadataClient(st.ac), metaURL)
	if err != nil {
		// The detail (connection refused vs. timeout vs. a non-JSON body)
		// goes to the log, not the result: this request runs against a
		// target the scan does not trust, and a warning that distinguishes
		// those outcomes is exactly what turns the scanner into a port
		// scanner for whoever is reading its own results back
		if st.ac.Log != nil {
			st.ac.Log.Debug("protected-resource metadata discovery failed", "url", metaURL, "error", err)
		}
		st.warnings = append(st.warnings, "protected-resource metadata discovery did not return usable metadata")
	} else if meta != nil {
		st.metadataFound = true
		if r, ok := meta["resource"].(string); ok {
			st.resourceURL = r
		}
		if servers, ok := meta["authorization_servers"].([]any); ok {
			for _, s := range servers {
				if str, ok := s.(string); ok {
					st.authServers = append(st.authServers, str)
				}
			}
		}
	}

	var findings []model.Finding
	if !st.tlsUsed {
		findings = append(findings, finding(
			"auth.plaintext_transport", "insecure_transport",
			"MCP endpoint is not using TLS",
			model.SeverityMedium, 0.9, model.EvidenceProtocol,
			"The connection to this target is plain HTTP; bearer tokens and session ids travel unencrypted.",
			model.Evidence{
				Level: model.EvidenceProtocol, Kind: "transport", Description: "transport scheme",
				Data: map[string]any{"url": st.target.RedactedURL()},
			},
		))
	}
	if f := checkResourceIdentifier(st, metaURL); f != nil {
		findings = append(findings, *f)
	}
	if f := checkAuthServerOrigin(st, metaURL); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

// checkResourceIdentifier flags a protected-resource metadata document whose "resource"
// field names something other than the target the scanner actually connected to. RFC 9728 uses
// that field to identify the protected resource, so a mismatch points to stale or wrong metadata.
func checkResourceIdentifier(st *state, metaURL string) *model.Finding {
	if st.resourceURL == "" {
		return nil
	}
	resource, err1 := url.Parse(st.resourceURL)
	target, err2 := url.Parse(st.target.URL)
	if err1 != nil || err2 != nil || httpx.SameOrigin(resource, target) {
		return nil
	}
	f := finding(
		"auth.resource_identifier_mismatch", "broken_authentication",
		"Protected-resource metadata names a different resource than the target",
		model.SeverityMedium, 0.6, model.EvidenceProtocol,
		"The \"resource\" field in this target's protected-resource metadata does not identify the target itself, which RFC 9728 defines it to do; worth confirming this metadata is actually meant for this server.",
		metadataEvidence(metaURL, st.resourceURL, st.authServers),
	)
	return &f
}

// checkAuthServerOrigin flags a declared authorization server whose origin differs from the
// resource's own origin. Separate authorization origins are valid, so this is a review signal
// with moderate confidence rather than proof of a broken deployment.
func checkAuthServerOrigin(st *state, metaURL string) *model.Finding {
	if st.resourceURL == "" || len(st.authServers) == 0 {
		return nil
	}
	resource, err := url.Parse(st.resourceURL)
	if err != nil {
		return nil
	}
	var crossOrigin []string
	for _, raw := range st.authServers {
		as, err := url.Parse(raw)
		if err != nil || httpx.SameOrigin(resource, as) {
			continue
		}
		crossOrigin = append(crossOrigin, raw)
	}
	if len(crossOrigin) == 0 {
		return nil
	}
	f := finding(
		"auth.authorization_server_cross_origin", "broken_authentication",
		"Authorization server declared on a different origin than the resource",
		model.SeverityLow, 0.5, model.EvidenceProtocol,
		"At least one authorization server in this target's protected-resource metadata is on a different origin than the resource itself. That is a normal deployment shape, but it is also the shape a token-audience confusion is built from - worth confirming this target actually validates tokens are scoped to it specifically.",
		metadataEvidence(metaURL, st.resourceURL, crossOrigin),
	)
	return &f
}

func metadataEvidence(metaURL, resource string, authServers []string) model.Evidence {
	redactedServers := make([]string, len(authServers))
	for i, s := range authServers {
		redactedServers[i] = redactURL(s)
	}
	return model.Evidence{
		Level:       model.EvidenceProtocol,
		Kind:        "auth_probe",
		Description: "protected-resource metadata",
		Data: map[string]any{
			// Normally a no-op: wellKnownURL already drops the userinfo and
			// the query. It is not a no-op on the one path where url.Parse
			// refused the target and wellKnownURL handed the URL back as
			// typed, which is exactly when a credential was most likely
			// hand-written into it.
			"request":  map[string]any{"method": "GET", "url": redactURL(metaURL)},
			"response": map[string]any{"resource": redactURL(resource), "authorization_servers": redactedServers},
		},
	}
}

// redactURL applies the same redaction Target.RedactedURL gives the target's own URL to a
// URL read out of band, from the server's metadata response rather than typed by an
// operator. Such URLs may still carry userinfo or query tokens into evidence.
func redactURL(raw string) string {
	if raw == "" {
		return raw
	}
	return model.Target{URL: raw}.RedactedURL()
}

func wellKnownURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	u.User = nil
	u.Path = "/.well-known/oauth-protected-resource"
	u.RawQuery = ""
	return u.String()
}

// fetchProtectedResourceMetadata GETs RFC 9728's well-known path through the supplied client.
// Production obtains that client from Analyzer.metadataClient with internal/httpx guards; tests
// may inject one directly.
func (a *Analyzer) fetchProtectedResourceMetadata(ctx context.Context, client *http.Client, metaURL string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	// The body comes from the scanned server, which is free to answer with an endless JSON
	// object: bounded the same way every other outbound read in the scanner is (npm 1 MiB, pypi
	// 4 MiB, osv 8 MiB)
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMetadataBytes)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

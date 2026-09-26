package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// Policy toggles one auth behavior at a time, so a test can build a
// vulnerable server and its fixed counterpart by flipping exactly the field
// under test and leaving everything else secure
type Policy struct {
	// AcceptAnyToken skips signature/audience/issuer/expiry/scope
	// validation entirely: any Authorization header, even garbage or none,
	// is treated as authenticated
	AcceptAnyToken bool

	// AcceptAnyBearer accepts any non-empty bearer value without validating it
	AcceptAnyBearer bool

	CheckAudience bool
	Audience      string
	CheckIssuer   bool
	Issuer        string
	CheckExpiry   bool
	CheckScope    bool
	RequiredScope string

	// SessionIDStyle controls how a new session id is minted.
	//   "random"    - crypto/rand, 128 bits of entropy (secure default)
	//   "sequential" - "session-1", "session-2", ... (guessable)
	SessionIDStyle string

	// AllowClientSessionID accepts a client-supplied Mcp-Session-Id at
	// initialize instead of always minting the server's own (session
	// fixation)
	AllowClientSessionID bool

	// BindSessionToUser re-checks, on every tools/call, that the bearer token's subject still
	// matches the session's original owner
	BindSessionToUser bool

	// HonorSessionTermination makes a DELETE actually invalidate the
	// session. Without it, a "closed" session id keeps working.
	HonorSessionTermination bool

	// RejectMalformedSession returns 400 for an unrecognized session id.
	// Without it, an unrecognized id falls back to an anonymous success
	// instead of a rejection.
	RejectMalformedSession bool

	// MetadataResource overrides the "resource" field of the
	// protected-resource metadata document. Empty means the server's own
	// URL, the correct value RFC 9728 defines that field to hold.
	MetadataResource string
	// MetadataAuthServers overrides "authorization_servers". Empty means a
	// single entry naming the server's own origin.
	MetadataAuthServers []string
}

// Secure returns a policy with every check enabled - the fixed baseline a
// test starts from before flipping one field back off to build the
// vulnerable counterpart
func Secure() Policy {
	return Policy{
		CheckAudience: true, Audience: "mcp-test-resource",
		CheckIssuer: true, Issuer: "https://mock-as.invalid",
		CheckExpiry: true,
		CheckScope:  true, RequiredScope: "tools:call",
		SessionIDStyle:          "random",
		BindSessionToUser:       true,
		HonorSessionTermination: true,
		RejectMalformedSession:  true,
	}
}

// Server is an MCP-shaped HTTP server whose auth behavior is driven by a Policy. It initializes
// sessions and exposes one whoami tool so tests can distinguish accepted identities and rejections.
type Server struct {
	*httptest.Server
	policy Policy

	mu       sync.Mutex
	sessions map[string]string // session id -> owner subject
	seq      int
}

// New starts a Server enforcing policy
func New(policy Policy) *Server {
	s := &Server{policy: policy, sessions: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleMetadata)
	mux.HandleFunc("/", s.handleRPC)
	s.Server = httptest.NewServer(mux)
	return s
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	resource := s.policy.MetadataResource
	if resource == "" {
		resource = s.URL
	}
	authServers := s.policy.MetadataAuthServers
	if len(authServers) == 0 {
		authServers = []string{s.URL}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"resource":              resource,
		"authorization_servers": authServers,
	})
}

type rpcRequest struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.handleTerminate(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(w, r, req)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		s.handleToolsList(w, r, req)
	case "tools/call":
		s.handleToolCall(w, r, req)
	default:
		writeRPCError(w, req.ID, -32601, "method not found")
	}
}

func (s *Server) handleInitialize(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	claims, tokenErr := s.authenticate(r)
	if tokenErr != "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	id := s.newSessionID(r)
	s.mu.Lock()
	s.sessions[id] = claims.Subject
	s.mu.Unlock()

	w.Header().Set("Mcp-Session-Id", id)
	w.Header().Set("Content-Type", "application/json")
	writeRPCResult(w, req.ID, map[string]any{
		"protocolVersion": "2024-11-05",
		"serverInfo":      map[string]any{"name": "mock-mcp-auth-target", "version": "1.0"},
		"capabilities":    map[string]any{"tools": map[string]any{}},
	})
}

// checkSession is the session-liveness gate shared by every method that requires an
// established session: is the id recognized, and (per policy) does the caller's current
// token still match the session's original owner
func (s *Server) checkSession(r *http.Request) (owner string, status int) {
	sessionID := r.Header.Get("Mcp-Session-Id")

	s.mu.Lock()
	owner, known := s.sessions[sessionID]
	s.mu.Unlock()

	if !known {
		if s.policy.RejectMalformedSession {
			return "", http.StatusBadRequest
		}
		return "anonymous", 0
	}
	if s.policy.BindSessionToUser {
		claims, tokenErr := s.authenticate(r)
		if tokenErr != "" || claims.Subject != owner {
			return "", http.StatusForbidden
		}
		return claims.Subject, 0
	}
	return owner, 0
}

func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	if _, status := s.checkSession(r); status != 0 {
		w.WriteHeader(status)
		return
	}
	writeRPCResult(w, req.ID, map[string]any{
		"tools": []any{map[string]any{"name": "whoami", "description": "returns the caller's identity"}},
	})
}

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request, req rpcRequest) {
	identity, status := s.checkSession(r)
	if status != 0 {
		w.WriteHeader(status)
		return
	}

	if req.Params.Name != "whoami" {
		writeRPCError(w, req.ID, -32602, "unknown tool")
		return
	}
	writeRPCResult(w, req.ID, map[string]any{
		"content": []any{map[string]any{"type": "text", "text": identity}},
	})
}

func (s *Server) handleTerminate(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("Mcp-Session-Id")
	if s.policy.HonorSessionTermination {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// authenticate validates the Authorization header per policy and returns
// the resulting claims. tokenErr is empty on success
func (s *Server) authenticate(r *http.Request) (Claims, string) {
	h := r.Header.Get("Authorization")
	if s.policy.AcceptAnyToken {
		token := strings.TrimPrefix(h, "Bearer ")
		claims, _ := VerifyJWT(token) // may fail to parse entirely; that's fine, still "authenticated"
		if claims.Subject == "" {
			claims.Subject = "unknown"
		}
		return claims, ""
	}
	if !strings.HasPrefix(h, "Bearer ") {
		return Claims{}, "missing bearer token"
	}
	if s.policy.AcceptAnyBearer {
		claims, _ := VerifyJWT(strings.TrimPrefix(h, "Bearer "))
		if claims.Subject == "" {
			claims.Subject = "unknown"
		}
		return claims, ""
	}
	claims, ok := VerifyJWT(strings.TrimPrefix(h, "Bearer "))
	if !ok {
		return Claims{}, "invalid signature"
	}
	if s.policy.CheckExpiry && claims.Expired() {
		return Claims{}, "expired"
	}
	if s.policy.CheckAudience && claims.Audience != s.policy.Audience {
		return Claims{}, "wrong audience"
	}
	if s.policy.CheckIssuer && claims.Issuer != s.policy.Issuer {
		return Claims{}, "wrong issuer"
	}
	if s.policy.CheckScope && !claims.HasScope(s.policy.RequiredScope) {
		return Claims{}, "insufficient scope"
	}
	return claims, ""
}

func (s *Server) newSessionID(r *http.Request) string {
	if s.policy.AllowClientSessionID {
		if client := r.Header.Get("Mcp-Session-Id"); client != "" {
			return client
		}
	}
	switch s.policy.SessionIDStyle {
	case "sequential":
		s.mu.Lock()
		s.seq++
		n := s.seq
		s.mu.Unlock()
		return "session-" + strconv.Itoa(n)
	default:
		b := make([]byte, 16)
		rand.Read(b)
		return hex.EncodeToString(b)
	}
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}

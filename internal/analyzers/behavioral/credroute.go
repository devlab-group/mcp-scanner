package behavioral

import (
	"regexp"
	"strings"
)

// A handler that reads a credential and makes a network call is usually a server signing in to
// its own service. What tells a leak from that is where the credential goes: to a request whose
// address the caller chooses, or into the tool's result, versus only to requests whose address
// starts with the server's own fixed or configured host. credRoute reads that from the names along
// the handler's calls (walkFlow); when it cannot tell, it says so.

type credRoute int

const (
	// credUnknown: a credential is read, but not traced to a request or to the result, or a request
	// that carries it has an address the names do not settle
	credUnknown credRoute = iota
	// credLeak: the credential reaches a request whose address the caller's data starts, or the
	// tool's own result
	credLeak
	// credOwnService: every request that carries the credential is addressed to a fixed or
	// configured host
	credOwnService
)

var (
	stringLit = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
	// address keywords of request calls
	addressKeywords = map[string]bool{"url": true, "uri": true, "endpoint": true, "baseURL": true, "base_url": true, "href": true, "host": true}
	// a request built with the method first: http.NewRequest("GET", url, body)
	methodFirst = regexp.MustCompile(`NewRequest(?:WithContext)?$`)
	schemeHost  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	leadIdent   = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*`)
)

var (
	// what makes a key a credential: auth_key, clientKey, signing_key - not item_key, cacheKey
	credKeyKinds = map[string]bool{"secret": true, "auth": true, "client": true, "app": true, "master": true, "signing": true,
		"sign": true, "encryption": true, "license": true, "service": true, "account": true, "session": true, "ssh": true,
		"consumer": true, "subscription": true, "bot": true, "webhook": true, "admin": true, "deploy": true, "hmac": true,
		"jwt": true, "gpg": true, "pgp": true, "write": true, "read": true}
	// tokens that are positions, not credentials: next_token, pageToken
	positionTokens = map[string]bool{"next": true, "page": true, "continuation": true, "cursor": true, "sync": true,
		"resume": true, "pagination": true, "start": true, "end": true, "last": true, "first": true, "prev": true, "previous": true}
	nameParts = regexp.MustCompile(`[A-Z]?[a-z0-9]+|[A-Z]+(?:[^a-z]|$)`)
)

// credName reports whether an identifier is named like a credential: an API or access key, a
// token, a secret, a password - not a bare key (a dictionary key), keys, a key of something
// (item_key, cacheKey), a count of tokens, or a page token
func credName(id string) bool {
	l := strings.ToLower(id)
	if l == "key" || l == "keys" || strings.Contains(l, "tokens") || strings.HasSuffix(l, "keyword") {
		return false
	}
	for _, w := range []string{"secret", "password", "passwd", "credential", "bearer", "apikey", "api_key", "accesskey", "access_key", "privatekey", "private_key"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	// the word before the last: auth in auth_key, page in pageToken
	var parts []string
	for _, p := range nameParts.FindAllString(strings.ReplaceAll(id, "_", " "), -1) {
		parts = append(parts, strings.ToLower(strings.TrimSpace(p)))
	}
	before := ""
	if len(parts) >= 2 {
		before = parts[len(parts)-2]
	}
	switch {
	case l == "token" || strings.HasPrefix(l, "token_"):
		return true
	case strings.HasSuffix(l, "_token") || strings.HasSuffix(id, "Token"):
		return !positionTokens[before]
	case strings.HasSuffix(l, "_key") || len(id) > 3 && strings.HasSuffix(id, "Key"):
		return credKeyKinds[before]
	}
	return false
}

// carriesCredential reports whether a call's arguments carry a credential: a name the server
// assigned from a credential read, or an identifier named like one outside string literals
func carriesCredential(text string, cred map[string]bool) bool {
	if mentionsAny(text, cred) || readsCredential(text) {
		return true
	}
	for _, id := range identWord.FindAllString(codeText(text), -1) {
		if credName(id) {
			return true
		}
	}
	return false
}

// addressOf is the text of a request call's address argument, or ""
func addressOf(nc netCall) string {
	args := nc.call.Args
	for _, a := range args {
		if addressKeywords[a.Keyword] {
			return strings.TrimSpace(a.Text)
		}
	}
	var positional []string
	for _, a := range args {
		if a.Keyword == "" {
			positional = append(positional, strings.TrimSpace(a.Text))
		}
	}
	i := 0
	if methodFirst.MatchString(nc.call.CalleeText) {
		i = 1
		if strings.HasSuffix(nc.call.CalleeText, "WithContext") {
			i = 2
		}
	}
	if i < len(positional) {
		return positional[i]
	}
	return ""
}

var (
	// an address handed on as text: String(url), str(url), url.toString(), url.href
	addrWrapped = regexp.MustCompile(`^(?:String|str)\((.+)\)$|^(.+?)\s*\.\s*(?:toString\(\)|href)$`)
	// an address resolved against a base: new URL(path, base), urljoin(base, path)
	addrAgainst = regexp.MustCompile(`^new\s+URL\((.+)\)$|^(?:urllib\.parse\.|parse\.)?urljoin\((.+)\)$`)
)

// addrStart reads where an address expression starts, as addressKind does, through the forms an
// address is handed on in - wrapped as text, awaited, resolved against a base - and treating the
// result of any other call as not settled
func addrStart(expr string, caller map[string]bool) string {
	e := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expr), "await "))
	e = strings.TrimSpace(strings.TrimSuffix(e, ";"))
	for k := 0; k < 3; k++ {
		m := addrWrapped.FindStringSubmatch(e)
		if m == nil {
			break
		}
		e = strings.TrimSpace(m[1] + m[2])
	}
	if m := addrAgainst.FindStringSubmatch(e); m != nil {
		if m[1] != "" {
			// new URL(path, base): the base decides; new URL(address) is the address
			parts := splitParams(m[1])
			return addrStart(parts[len(parts)-1], caller)
		}
		parts := splitParams(m[2])
		return addrStart(parts[0], caller)
	}
	if lead := leadIdent.FindString(e); lead == "new" || lead != "" && strings.HasPrefix(strings.TrimSpace(e[len(lead):]), "(") {
		return "" // what another call or a constructor returns
	}
	return addressKind(e, caller)
}

// addressKind reads where an address starts: "caller" when the caller's data starts it or its
// host, "own" when a fixed or configured host does, "" when the text does not settle it
func addressKind(addr string, caller map[string]bool) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return ""
	}
	// f"...", `...`, "..." + x: look at the start of the text inside the literal
	body, interp := "", false
	switch {
	case strings.HasPrefix(a, "f\"") || strings.HasPrefix(a, "f'"):
		body, interp = a[2:], true
	case strings.HasPrefix(a, "`"):
		body, interp = a[1:], true
	case strings.HasPrefix(a, "\"") || strings.HasPrefix(a, "'"):
		q := a[:1]
		end := strings.Index(a[1:], q)
		if end < 0 {
			return ""
		}
		body = a[1 : 1+end]
		rest := strings.TrimSpace(a[2+end:])
		if strings.HasPrefix(body, "/") {
			return "own" // a path on a client whose base is configured
		}
		if m := schemeHost.FindString(body); m != "" {
			host := body[len(m):]
			if host != "" && !strings.ContainsAny(host, "{$%") {
				return "own" // a literal origin; what follows it is a path
			}
			if host == "" && strings.HasPrefix(rest, "+") && mentionsAny(leadIdent.FindString(strings.TrimSpace(rest[1:])), caller) {
				return "caller" // "https://" + host
			}
		}
		return ""
	default:
		lead := leadIdent.FindString(a)
		if lead == "" {
			return ""
		}
		first := identWord.FindString(lead)
		if caller[first] {
			return "caller"
		}
		return "own" // a constant or a setting: API, BASE_URL, self.base_url, config.url
	}
	if interp {
		start := func(s string) (string, bool) {
			// {name} or ${name} at the very start of the text
			s = strings.TrimPrefix(s, "$")
			if !strings.HasPrefix(s, "{") {
				return "", false
			}
			return identWord.FindString(s[1:]), true
		}
		if name, ok := start(body); ok {
			if caller[name] {
				return "caller"
			}
			return "own"
		}
		if strings.HasPrefix(body, "/") {
			return "own"
		}
		if m := schemeHost.FindString(body); m != "" {
			host := body[len(m):]
			if name, ok := start(host); ok {
				if caller[name] {
					return "caller"
				}
				return ""
			}
			if i := strings.IndexAny(host, "/{$"); i > 0 && (host[i] == '/') {
				return "own"
			}
			if !strings.ContainsAny(host, "{$") {
				return "own"
			}
		}
	}
	return ""
}

// route is where the credentials the handler reads go
func (fl *flow) route() credRoute {
	if fl.returnsCred {
		return credLeak
	}
	carried, own := 0, 0
	for _, nc := range fl.net {
		var args []string
		for _, a := range nc.call.Args {
			args = append(args, a.Text)
		}
		if !carriesCredential(strings.Join(args, ", "), fl.cred[nc.sym]) {
			continue
		}
		carried++
		switch addrStart(addressOf(nc), fl.effectiveCaller(nc.sym)) {
		case "caller":
			return credLeak
		case "own":
			own++
		}
	}
	if carried > 0 && own == carried {
		return credOwnService
	}
	return credUnknown
}

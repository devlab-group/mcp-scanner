package promptdefense

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/revinand/mcp-scanner/pkg/model"
)

// evaluate dispatches a compiled rule to the detector its Type names
func (r *compiledRule) evaluate(units []unit) []model.Finding {
	switch r.Type {
	case "", "pattern":
		return r.matchPattern(units)
	}
	// Every other rule type reads the shape of the text rather than what it says, and
	// normalizing is exactly what changes that shape: the fold strips the hidden characters
	// findHiddenChars exists to find, and turns a word written entirely in Cyrillic into one
	// where only the letters with Latin twins were replaced, which is the mixed script
	// findConfusables reports
	units = withoutNormalized(units)
	switch r.Type {
	case "hidden_chars":
		return r.matchStructural(units, findHiddenChars, "hidden_characters")
	case "confusable_script":
		return r.matchStructural(units, findConfusables, "mixed_script")
	case "base64_blob":
		return r.matchStructural(units, findBase64Blobs, "base64_blob")
	case "oversized_description":
		return r.matchOversizedDescription(units)
	case "conflicting_metadata":
		return r.matchConflictingMetadata(units)
	}
	return nil
}

// withoutNormalized drops the synthetic folded units expandUnits added
func withoutNormalized(units []unit) []unit {
	out := make([]unit, 0, len(units))
	for _, u := range units {
		if strings.HasSuffix(u.field, ":normalized") {
			continue
		}
		out = append(out, u)
	}
	return out
}

func (r *compiledRule) appliesTo(u unit) bool {
	if len(r.Fields) == 0 {
		return true
	}
	for _, f := range r.Fields {
		if f == u.field || (f == "argument" && strings.HasPrefix(u.field, "argument:")) {
			return true
		}
	}
	return false
}

// matchPattern keeps ordinary pattern hits visible. Qualifiers lower severity one step and set
// confidence to 0.3; quotation lowers confidence and, with a qualifier, sets severity to LOW. For
// ContextIsPremise rules, missing required context means no match. Windows stay within one
// sentence, and negateBefore looks only before the match.
func (r *compiledRule) matchPattern(units []unit) []model.Finding {
	var out []model.Finding
	for _, u := range units {
		if !r.appliesTo(u) {
			continue
		}
		var downgraded *model.Finding
		for _, p := range r.patterns {
			loc := p.FindStringIndex(u.text)
			if loc == nil {
				continue
			}
			start, end := loc[0], loc[1]
			lo, hi := r.windowBounds(u.text, start, end)
			window := u.text[lo:hi]
			before := u.text[lo:start]

			level := model.EvidenceLevel(strings.ToUpper(r.Evidence))
			kind := "pattern_match"
			if r.PromoteIfStructural != "" && structuralHit(r.PromoteIfStructural, u.text) {
				level = model.EvidenceStatic
				kind = "pattern_match+structural"
			}

			if len(r.requireContext) > 0 && r.ContextIsPremise && !anyMatch(r.requireContext, window) {
				// For a rule whose require_context list is the other half of its own claim -
				// credential-harvesting's handover verbs, exfiltration's send verbs - the absence of
				// that half is not a qualifier; the rule simply does not match
				continue
			}
			if reason := r.downgradeReason(window, before); reason != "" {
				// Keep only the first suppressed candidate per unit: if a
				// later pattern in this same rule matches cleanly, that
				// clean finding is the one worth reporting, and the
				// downgraded candidate below is discarded rather than
				// added on top of it
				if downgraded == nil {
					f := r.suppressedFinding(u, start, end, level, kind, reason, quotedSpan(u.text, start, end))
					downgraded = &f
				}
				continue
			}

			f := r.finding(u, start, end, level)
			f.Evidence[0].Kind = kind
			if quotedSpan(u.text, start, end) {
				f = r.quotedFinding(f, u, start, end)
			}
			out = append(out, f)
			downgraded = nil
			break // one finding per rule per unit is enough signal, and a clean match outranks a downgraded one
		}
		if downgraded != nil {
			out = append(out, *downgraded)
		}
	}
	return out
}

// suppressedConfidence is the confidence given to a downgraded finding. It
// is a fixed low value rather than a fraction of the rule's own confidence,
// since the point is "this needs a second look", not a scaled-down version
// of how sure the original match was.
const suppressedConfidence = 0.3

// quotedConfidence is the confidence given to a match inside paired quotes or
// backticks. Quoting alone lowers confidence but not severity because the target
// controls the match and punctuation.
const quotedConfidence = 0.5

// downgradeReason names the qualifier that argues against a match, or "" if
// none does. Both qualifiers live in the same attacker-controlled text as
// the match, so neither erases it; they select the downgraded finding
// instead of the full one.
func (r *compiledRule) downgradeReason(window, before string) string {
	if len(r.requireContext) > 0 && !r.ContextIsPremise && !anyMatch(r.requireContext, window) {
		return "none of the context this rule corroborates a match with appeared in the same sentence"
	}
	if anyMatch(r.negate, window) || anyMatch(r.negateBefore, before) {
		return "a negate qualifier matched in the same sentence as this match"
	}
	return ""
}

// suppressedFinding downgrades a pattern match that a qualifier argued against instead of
// dropping it. A qualifier costs one severity step; quoting as well sets severity to LOW. The
// match remains observable even when those author-written signals reduce its priority.
func (r *compiledRule) suppressedFinding(u unit, start, end int, level model.EvidenceLevel, kind, reason string, quoted bool) model.Finding {
	f := r.finding(u, start, end, level)
	f.Title = "Suppressed by qualifier: " + r.Title
	f.Severity = f.Severity.OneStepDown()
	if quoted {
		f.Severity = model.SeverityLow
	}
	f.Confidence = suppressedConfidence
	f.Description = fmt.Sprintf(
		"%s This is reported at reduced severity and confidence instead of dropped because %s: the qualifier "+
			"is part of the same author-controlled text as the match it qualifies and does not retract it.",
		r.Description, reason)
	f.Evidence[0].Kind = kind + "_suppressed"
	f.Evidence[0].Description = fmt.Sprintf(
		"%s matched in %s but %s, reducing severity and confidence: %q",
		r.ID, u.locator(), reason, snippet(u.text, start, end))
	return f
}

// quotedFinding annotates a match inside paired quotes or backticks. A quotation
// may be a citation, so it lowers confidence without changing severity on its own.
func (r *compiledRule) quotedFinding(f model.Finding, u unit, start, end int) model.Finding {
	f.Confidence = quotedConfidence
	f.Description += " The matched text is quoted, which may mean it is cited rather than " +
		"issued; confidence is reduced, but quoting alone does not lower severity."
	f.Evidence[0].Kind += "_quoted"
	f.Evidence[0].Description = fmt.Sprintf(
		"%s matched in %s inside quote marks, at reduced confidence: %q",
		r.ID, u.locator(), snippet(u.text, start, end))
	return f
}

// windowBounds returns the byte range around a match that require_context, negate and
// negateBefore search: the current sentence, further narrowed to Proximity characters on
// each side when the rule sets one. Sentence bounds keep a qualifier in nearby prose from
// suppressing an unrelated match in the next sentence.
func (r *compiledRule) windowBounds(text string, start, end int) (lo, hi int) {
	lo, hi = 0, len(text)
	if r.Proximity > 0 {
		lo, hi = start-r.Proximity, end+r.Proximity
		if lo < 0 {
			lo = 0
		}
		if hi > len(text) {
			hi = len(text)
		}
	}
	lo = sentenceFloor(text, lo, start)
	hi = sentenceCeil(text, end, hi)
	for lo > 0 && !utf8.RuneStart(text[lo]) {
		lo--
	}
	for hi < len(text) && !utf8.RuneStart(text[hi]) {
		hi++
	}
	return lo, hi
}

// sentenceFloor pulls lo forward to just after the nearest sentence
// boundary before start, if one exists at or after lo
func sentenceFloor(text string, lo, start int) int {
	for i := start - 1; i >= lo; i-- {
		if sentenceEndAt(text, i) {
			return i + 1
		}
	}
	return lo
}

// sentenceCeil pulls hi back to just after the nearest sentence boundary
// at or after end, if one exists before hi
func sentenceCeil(text string, end, hi int) int {
	for i := end; i < hi; i++ {
		if sentenceEndAt(text, i) {
			return i + 1
		}
	}
	return hi
}

// sentenceEndAt reports whether text[i] ends a sentence. A period only
// counts when whitespace (or the end of the text) follows it - "1.5" and
// "config.yaml" are not sentence ends - and not when a single letter
// precedes it, which marks an abbreviation ("e.g.", "i.e.") rather than a
// word ending a sentence.
func sentenceEndAt(text string, i int) bool {
	switch text[i] {
	case '\n', '!', '?':
		return true
	case '.':
	default:
		return false
	}
	if i+1 < len(text) && text[i+1] != ' ' && text[i+1] != '\t' && text[i+1] != '\n' {
		return false
	}
	if i > 0 && isASCIILetter(text[i-1]) && (i < 2 || !isASCIILetter(text[i-2])) {
		return false
	}
	return true
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// quotedSpan reports whether the match at [start,end) sits directly inside a matching pair
// of quote marks or backticks - some evidence that 'ignore previous instructions' next to a
// rule name cites the phrase a security tool detects rather than issuing it. Evidence only:
// it lowers confidence, it does not decide whether the finding exists.
func quotedSpan(text string, start, end int) bool {
	// Pairs are found by scanning the whole text rather than by testing the bytes either side
	// of the match, so a citation longer than the pattern hit - `do not tell the user`, where
	// the pattern matched only "do not tell" - still counts as quoted
	for _, q := range []byte{'`', '"', '\''} {
		open := -1
		for i := 0; i < len(text); i++ {
			if text[i] != q {
				continue
			}
			if open < 0 {
				open = i
				continue
			}
			if open < start && end <= i {
				return true
			}
			open = -1
		}
	}
	return false
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func structuralHit(name, text string) bool {
	switch name {
	case "hidden_chars":
		return len(findHiddenChars(text)) > 0
	case "confusable_script":
		return len(findConfusables(text)) > 0
	case "base64_blob":
		return len(findBase64Blobs(text)) > 0
	case "valid_url":
		return len(findValidURLs(text)) > 0
	}
	return false
}

// finding builds the common shape every detector reports: the rule's static
// metadata plus one piece of evidence pointing at the matched span
func (r *compiledRule) finding(u unit, start, end int, level model.EvidenceLevel) model.Finding {
	return model.Finding{
		RuleID:        r.ID,
		Category:      r.Category,
		Title:         r.Title,
		Severity:      model.Severity(strings.ToUpper(r.Severity)),
		Confidence:    r.confidence(),
		EvidenceLevel: level,
		File:          u.locator(),
		Tool:          u.capability,
		Description:   r.Description,
		Remediation:   r.Remediation,
		Analyzer:      analyzerName,
		Evidence: []model.Evidence{{
			Level:       level,
			Description: fmt.Sprintf("%s matched in %s", r.ID, u.locator()),
			Snippet:     snippet(u.text, start, end),
		}},
	}
}

// span is one structural match: a byte range in the unit text plus a short
// note on what was found there
type span struct {
	start, end int
	note       string
}

// matchStructural wraps a structural detector (one that returns every match
// span in a string) into a rule: the first span becomes the finding's
// evidence, and additional occurrences are counted in the description
func (r *compiledRule) matchStructural(units []unit, find func(string) []span, kind string) []model.Finding {
	var out []model.Finding
	for _, u := range units {
		if !r.appliesTo(u) {
			continue
		}
		spans := find(u.text)
		if len(spans) == 0 {
			continue
		}
		level := model.EvidenceLevel(strings.ToUpper(r.Evidence))
		sp := spans[0]
		f := r.finding(u, sp.start, sp.end, level)
		f.Evidence[0].Kind = kind
		f.Evidence[0].Description = fmt.Sprintf("%s: %s", r.ID, sp.note)
		if len(spans) > 1 {
			f.Description = fmt.Sprintf("%s (%d occurrences in this field)", r.Description, len(spans))
		}
		out = append(out, f)
	}
	return out
}

// hiddenChars are invisible code points used to hide or reorder text. A BOM at the start of a
// unit is allowed because editors may prepend one to a document; the same code point elsewhere
// remains suspicious.
var hiddenChars = map[rune]string{
	'\u00AD': "soft hyphen",
	'\u034F': "combining grapheme joiner",
	'\u180E': "Mongolian vowel separator",
	'\u200B': "zero-width space",
	'\u200C': "zero-width non-joiner",
	'\u200D': "zero-width joiner",
	'\u2060': "word joiner",
	'\uFEFF': "zero-width no-break space (BOM)",
	'\u202A': "left-to-right embedding (bidi override)",
	'\u202B': "right-to-left embedding (bidi override)",
	'\u202C': "pop directional formatting (bidi override)",
	'\u202D': "left-to-right override (bidi override)",
	'\u202E': "right-to-left override (bidi override)",
	'\u2066': "left-to-right isolate (bidi override)",
	'\u2067': "right-to-left isolate (bidi override)",
	'\u2068': "first strong isolate (bidi override)",
	'\u2069': "pop directional isolate (bidi override)",
}

// hiddenRanges are invisible-by-design blocks too wide to enumerate one code point at a
// time. Unicode tags can encode hidden ASCII, while variation selectors remain invisible but
// can still alter tokenizer input.
var hiddenRanges = []struct {
	lo, hi rune
	note   string
}{
	{0xE0000, 0xE007F, "Unicode tag character (ASCII-smuggling block)"},
	{0xFE00, 0xFE0F, "variation selector"},
}

// hiddenCharNote reports the reason r counts as a hidden character, if it
// does - a single entry in hiddenChars, or membership in one of
// hiddenRanges. Shared by findHiddenChars (detection) and escapeControl
// (evidence.go, so a snippet never renders one of these characters raw)
// rather than each keeping its own notion of what counts.
func hiddenCharNote(r rune) (string, bool) {
	if note, ok := hiddenChars[r]; ok {
		return note, true
	}
	for _, rg := range hiddenRanges {
		if r >= rg.lo && r <= rg.hi {
			return rg.note, true
		}
	}
	return "", false
}

func findHiddenChars(s string) []span {
	var out []span
	i := 0
	for _, r := range s {
		w := utf8.RuneLen(r)
		if r == '\uFEFF' && i == 0 {
			i += w
			continue
		}
		if note, ok := hiddenCharNote(r); ok {
			out = append(out, span{i, i + w, note})
		}
		i += w
	}
	return out
}

// minDecodedTagRun is the shortest decoded tag-block run worth
// re-classifying. A stray tag character or two carries no instruction for
// the text rules to find; findHiddenChars already flags its presence
// regardless of length.
const minDecodedTagRun = 4

// decodeTagRuns extracts every maximal run of Unicode tag characters (U+E0000-U+E007F) in s
// and decodes each one back to the ASCII text it encodes: a tag character at 0xE0000+cp
// stands for the ASCII byte cp. The decoded text is run through the rules again so a hidden
// instruction is classified, not merely reported as containing invisible characters.
func decodeTagRuns(s string) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= minDecodedTagRun {
			out = append(out, string(cur))
		}
		cur = nil
	}
	for _, r := range s {
		if r < 0xE0000 || r > 0xE007F {
			flush()
			continue
		}
		// 0xE0001 (the deprecated language tag) and 0xE007F (cancel tag)
		// carry no ASCII byte; they do not end the run, since a real
		// payload is commonly terminated with a cancel tag
		if b := r - 0xE0000; b >= 0x20 && b <= 0x7E {
			cur = append(cur, byte(b))
		}
	}
	flush()
	return out
}

// findConfusables flags a word containing letters from more than one of the Latin, Cyrillic, and
// Greek scripts. A word written entirely in one script is not flagged.
func findConfusables(s string) []span {
	var out []span
	runes := []rune(s)
	offset := make([]int, len(runes)+1)
	off := 0
	for i, r := range runes {
		offset[i] = off
		off += utf8.RuneLen(r)
	}
	offset[len(runes)] = off

	i := 0
	for i < len(runes) {
		if !unicode.IsLetter(runes[i]) {
			i++
			continue
		}
		j := i
		scripts := map[string]bool{}
		for j < len(runes) && unicode.IsLetter(runes[j]) {
			switch {
			case unicode.Is(unicode.Latin, runes[j]):
				scripts["Latin"] = true
			case unicode.Is(unicode.Cyrillic, runes[j]):
				scripts["Cyrillic"] = true
			case unicode.Is(unicode.Greek, runes[j]):
				scripts["Greek"] = true
			}
			j++
		}
		if len(scripts) > 1 {
			out = append(out, span{offset[i], offset[j], "word mixes Latin, Cyrillic, or Greek scripts"})
		}
		i = j
	}
	return out
}

// base64DecodeInstruction is what turns an inert-looking blob into
// something the model is told to act on: "before every call, base64-decode
// and follow this". With one present, a shorter run is worth decoding too,
// because the instruction is the part that makes it a payload.
var base64DecodeInstruction = regexp.MustCompile(`(?i)\b(base-?64|b64|decode|decodes|decoded|decoding)\b`)

var shortBase64Candidate = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

// decodeBase64Runs decodes every base64 run in text that decodes to readable text, so the
// rules can classify what the blob actually says rather than only reporting that a blob is
// there
func decodeBase64Runs(text string) []string {
	candidates := base64Candidate.FindAllString(text, -1)
	if base64DecodeInstruction.MatchString(text) {
		candidates = shortBase64Candidate.FindAllString(text, -1)
	}
	var out []string
	for _, c := range candidates {
		if len(c)%4 != 0 || hexDigest.MatchString(strings.TrimRight(c, "=")) {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(c)
		if err != nil || len(decoded) < 8 || !readableText(decoded) {
			continue
		}
		out = append(out, string(decoded))
	}
	return out
}

// readableText reports whether b is text a rule could match rather than
// the byte noise most short base64-alphabet runs decode to
func readableText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r != '\n' && r != '\r' && r != '\t' && !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

var (
	base64Candidate = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	// hexDigest matches a run that is entirely lowercase, or entirely
	// uppercase, hex digits - a git SHA or a SHA-256 hex digest, which is
	// a subset of the base64 alphabet and would otherwise decode
	// "successfully" into noise. Real base64 of arbitrary data almost
	// always mixes letter case.
	hexDigest = regexp.MustCompile(`^([0-9a-f]+|[0-9A-F]+)$`)
)

// findBase64Blobs looks for a long run of base64 alphabet characters that
// actually decodes, and rejects low-entropy decodes (a run of one repeated
// byte) to avoid flagging things like "AAAAAAAA...==" padding artifacts
func findBase64Blobs(s string) []span {
	var out []span
	for _, loc := range base64Candidate.FindAllStringIndex(s, -1) {
		cand := s[loc[0]:loc[1]]
		if len(cand)%4 != 0 {
			continue
		}
		if hexDigest.MatchString(strings.TrimRight(cand, "=")) {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(cand)
		if err != nil || len(decoded) < 16 {
			continue
		}
		distinct := map[byte]bool{}
		for _, b := range decoded {
			distinct[b] = true
		}
		if len(distinct) < 8 {
			continue
		}
		out = append(out, span{loc[0], loc[1], fmt.Sprintf("%d bytes of base64-decodable data", len(decoded))})
	}
	return out
}

var urlCandidate = regexp.MustCompile(`https?://[^\s"'<>)]+`)

// findValidURLs is the promotion check for exfiltration-style rules: a
// pattern match near the word "http" is a guess, a URL that actually parses
// with a host is a structural fact
func findValidURLs(s string) []span {
	var out []span
	for _, loc := range urlCandidate.FindAllStringIndex(s, -1) {
		u, err := url.Parse(s[loc[0]:loc[1]])
		if err == nil && u.Host != "" {
			out = append(out, span{loc[0], loc[1], "url"})
		}
	}
	return out
}

const (
	defaultMaxLength          = 1500
	defaultMaxLengthLowParams = 500
)

// countSchemaProperties reads the "properties" object of a JSON Schema
// input schema, the way MCP tool declarations shape it
func countSchemaProperties(schema map[string]any) int {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return 0
	}
	return len(props)
}

// matchOversizedDescription flags a tool description long enough, relative to its parameter count,
// to be more likely a place to hide instructions than to document the tool for a user
func (r *compiledRule) matchOversizedDescription(units []unit) []model.Finding {
	max := r.MaxLength
	if max <= 0 {
		max = defaultMaxLength
	}
	maxLowParams := r.MaxLengthLowParams
	if maxLowParams <= 0 {
		maxLowParams = defaultMaxLengthLowParams
	}

	var out []model.Finding
	for _, u := range units {
		if u.capKind != "tool" || u.field != "description" {
			continue
		}
		n := utf8.RuneCountInString(u.text)
		params := countSchemaProperties(u.inputSchema)
		switch {
		case n > max:
		case n > maxLowParams && params <= 1:
		default:
			continue
		}

		level := model.EvidenceLevel(strings.ToUpper(r.Evidence))
		end := len(u.text)
		if end > 200 {
			end = 200
			for end > 0 && !utf8.RuneStart(u.text[end]) {
				end--
			}
		}
		f := r.finding(u, 0, end, level)
		f.Evidence[0].Kind = "description_length"
		f.Evidence[0].Description = fmt.Sprintf("%s: %d characters, %d declared input parameter(s)", r.ID, n, params)
		out = append(out, f)
	}
	return out
}

// matchConflictingMetadata reuses the rule's patterns as the "this changes state" verb list
// and negate as the "explicitly does not" qualifiers; the structural part is pairing that
// against the tool's own readOnlyHint annotation, which a regex over one field cannot do
func (r *compiledRule) matchConflictingMetadata(units []unit) []model.Finding {
	var out []model.Finding
	for _, u := range units {
		if u.capKind != "tool" || u.field != "description" {
			continue
		}
		if !readOnlyHint(u.annotations) {
			continue
		}
		for _, p := range r.patterns {
			loc := p.FindStringIndex(u.text)
			if loc == nil {
				continue
			}
			start, end := loc[0], loc[1]
			lo, hi := r.windowBounds(u.text, start, end)
			window := u.text[lo:hi]
			before := u.text[lo:start]
			level := model.EvidenceLevel(strings.ToUpper(r.Evidence))
			if reason := r.downgradeReason(window, before); reason != "" {
				f := r.suppressedFinding(u, start, end, level, "annotation_conflict", reason, quotedSpan(u.text, start, end))
				f.Evidence[0].Description = fmt.Sprintf(
					"%s: annotations mark this tool readOnlyHint=true and the description says %q, "+
						"but %s, reducing severity and confidence",
					r.ID, u.text[start:end], reason)
				out = append(out, f)
				break
			}
			f := r.finding(u, start, end, level)
			f.Evidence[0].Kind = "annotation_conflict"
			f.Evidence[0].Description = fmt.Sprintf(
				"%s: annotations mark this tool readOnlyHint=true but the description says %q",
				r.ID, u.text[start:end],
			)
			if quotedSpan(u.text, start, end) {
				f = r.quotedFinding(f, u, start, end)
			}
			out = append(out, f)
			break
		}
	}
	return out
}

func readOnlyHint(ann map[string]any) bool {
	for k, v := range ann {
		if strings.EqualFold(k, "readOnlyHint") {
			b, ok := v.(bool)
			return ok && b
		}
	}
	return false
}

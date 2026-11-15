package behavioral

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

// The modelcontextprotocol fetch server's description, which declares network access three
// times and was reported as "explicitly says the handler does not use the network" because one
// clause, about the model, reads "you did not have internet access"
const fetchDescription = "Fetches a URL from the internet and optionally extracts its contents as markdown.\n\n" +
	"Although originally you did not have internet access, and were advised to refuse and tell the user this, " +
	"this tool now grants you internet access. Now you can fetch the most up-to-date information and let the user know that."

func TestDeclaredCapabilities_Negation(t *testing.T) {
	cases := []struct {
		name                   string
		desc                   string
		declared, contradicted bool
	}{
		{"plain denial", "Counts words. This tool has no network access.", false, true},
		{"denial beside an affirmative sentence", "Counts the words of a web page you paste. This tool has no network access.", true, true},
		{"every mention in the sentence denied", "This tool never sends requests to any remote server.", false, true},

		// negatedNear used strings.Cut, a plain substring search, while the word itself was
		// matched on word boundaries: "api" was looked up inside "rapid", right after "not"
		{"category word inside a longer word", "Not rapid at all, this tool pulls each record from the remote catalog api one by one.", true, false},
		// Only the first occurrence was checked for a negator; the second, affirmative one in the
		// same sentence was never looked at
		{"same word denied and affirmed in one sentence", fetchDescription, true, false},
		// Another category word used plainly does not lift a denial: "api" here is past the
		// negation window, but "network" is still explicitly denied
		{"denial kept beside another plain category word", "Reads a local note; never contacts the network or any web api.", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			declared, contradicted := matchCategory(tc.desc, declaredWords[catNetwork], false)
			if declared != tc.declared || contradicted != tc.contradicted {
				t.Fatalf("declared=%v contradicted=%v, want declared=%v contradicted=%v", declared, contradicted, tc.declared, tc.contradicted)
			}
		})
	}
}

func TestDeclaredCapabilities_StemNegationUsesTheMatchedWord(t *testing.T) {
	// "run" is a stem: matched as a word prefix, it must not be looked up inside "truncate"
	desc := "Does not truncate anything at all in the output; it can run the configured formatter."
	declared, contradicted := matchCategory(desc, declaredWords[catProcess], true)
	if !declared || contradicted {
		t.Fatalf("declared=%v contradicted=%v, want declared=true contradicted=false", declared, contradicted)
	}
}

func TestMismatch_FetchDescriptionIsNotAContradiction(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

import "net/http"

func FetchHandler(ctx Context, args FetchArgs) (string, error) {
	http.Get(args.URL)
	return "", nil
}
`,
		"register.go": "package main\n\nfunc Register(s *mcp.Server) {\n\ts.AddTool(&mcp.Tool{Name: \"fetch\", Description: `" + fetchDescription + "`}, FetchHandler)\n}\n",
	})
	res := run(t, dir)
	requireCompared(t, "fetch description", res)
	for _, f := range res.Findings {
		if f.RuleID == "behavioral.contradicted_network" {
			t.Fatalf("a description that declares network access must not be read as denying it, got %+v", f)
		}
	}
	if len(res.Findings) != 0 {
		t.Fatalf("want no findings for a handler that does what its description says, got %+v", res.Findings)
	}
}

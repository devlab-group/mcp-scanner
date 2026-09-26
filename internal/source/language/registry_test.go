package language

import "testing"

func TestForExt_RecognizesModuleVariantExtensions(t *testing.T) {
	cases := map[string]ID{
		".mts": TypeScript,
		".cts": TypeScript,
		".pyw": Python,
	}
	for ext, want := range cases {
		a := ForExt(ext)
		if a == nil {
			t.Errorf("%s: not recognized by any adapter", ext)
			continue
		}
		if a.ID != want {
			t.Errorf("%s: want %s, got %s", ext, want, a.ID)
		}
	}
}

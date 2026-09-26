package language

import "testing"

func TestAllGrammarsLoad(t *testing.T) {
	for _, a := range All() {
		lang, err := a.Language()
		if err != nil {
			t.Errorf("%s: %v", a.ID, err)
			continue
		}
		if lang == nil {
			t.Errorf("%s: nil language", a.ID)
		}
		for _, q := range []string{"symbols", "imports", "calls"} {
			if _, err := a.Query(q); err != nil {
				t.Errorf("%s/%s: %v", a.ID, q, err)
			}
		}
		if a.HasQuery("decorators") {
			if _, err := a.Query("decorators"); err != nil {
				t.Errorf("%s/decorators: %v", a.ID, err)
			}
		}
	}
}

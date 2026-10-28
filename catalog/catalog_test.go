package catalog

import "testing"

func TestCuratedCatalogIsNormalizedAndUnique(t *testing.T) {
	tools, err := Tools()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) < 14 {
		t.Fatalf("expected curated base, got %d tools", len(tools))
	}
	seen := map[string]bool{}
	for _, v := range tools {
		if seen[v.ID] {
			t.Fatalf("duplicate tool %s", v.ID)
		}
		seen[v.ID] = true
		if v.Title == "" || v.SourceURL == "" || v.Parser == "" || v.Documentation.Purpose == "" || len(v.InputSchema) == 0 || len(v.OutputSchema) == 0 {
			t.Fatalf("incomplete tool %s", v.ID)
		}
	}
	sources, err := Sources()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range sources {
		if v.Trust == "" || v.URL == "" {
			t.Fatalf("incomplete source %s", v.ID)
		}
	}
	skills, err := Skills()
	if err != nil {
		t.Fatal(err)
	}
	if len(skills) < 25 {
		t.Fatalf("expected at least 25 curated skills, got %d", len(skills))
	}
	for _, v := range skills {
		if v.ID == "" || v.Description == "" || v.Purpose == "" || v.Version == "" || len(v.Steps) == 0 || len(v.References) == 0 || v.Documentation.OutputSchema == "" {
			t.Fatalf("incomplete skill %s", v.ID)
		}
	}
}

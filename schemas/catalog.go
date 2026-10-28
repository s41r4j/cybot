// Package schemas embeds CYBOT's canonical JSON Schemas into the executable.
package schemas

import (
	"embed"
	"fmt"
	"sort"
)

//go:embed *.json
var files embed.FS

func Names() []string {
	entries, _ := files.ReadDir(".")
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name()[:len(e.Name())-5])
		}
	}
	sort.Strings(out)
	return out
}
func Get(name string) ([]byte, error) {
	b, err := files.ReadFile(name + ".json")
	if err != nil {
		return nil, fmt.Errorf("unknown schema %q", name)
	}
	return b, nil
}
func Must(name string) []byte {
	b, err := Get(name)
	if err != nil {
		panic(err)
	}
	return b
}

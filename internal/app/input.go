package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Plan and execution must review the same bounded object, including when a
// file grows between its initial stat and the actual read.
func readCapabilityInput(path string) (json.RawMessage, error) {
	if path == "" {
		return json.RawMessage(`{}`), nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("input-file must be a regular JSON file of at most 1 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input-file must remain a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("input-file exceeds 1 MiB")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return nil, fmt.Errorf("input-file must contain one JSON object")
	}
	return data, nil
}

package schemas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	compileOnce sync.Once
	compiled    map[string]*jsonschema.Schema
	compileErr  error
)

func compileAll() {
	compiled = map[string]*jsonschema.Schema{}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	for _, name := range Names() {
		data, err := Get(name)
		if err != nil {
			compileErr = err
			return
		}
		var document any
		if err = json.Unmarshal(data, &document); err != nil {
			compileErr = fmt.Errorf("decode schema %s: %w", name, err)
			return
		}
		if err = compiler.AddResource("cybot://schemas/"+name, document); err != nil {
			compileErr = fmt.Errorf("add schema %s: %w", name, err)
			return
		}
	}
	for _, name := range Names() {
		s, err := compiler.Compile("cybot://schemas/" + name)
		if err != nil {
			compileErr = fmt.Errorf("compile schema %s: %w", name, err)
			return
		}
		compiled[name] = s
	}
}

// Validate checks a Go value against one canonical embedded CYBOT schema.
func Validate(name string, value any) error {
	compileOnce.Do(compileAll)
	if compileErr != nil {
		return compileErr
	}
	s, ok := compiled[name]
	if !ok {
		return fmt.Errorf("unknown schema %q", name)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal %s value: %w", name, err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err = decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode %s value: %w", name, err)
	}
	if err = s.Validate(document); err != nil {
		return fmt.Errorf("%s schema: %w", name, err)
	}
	return nil
}

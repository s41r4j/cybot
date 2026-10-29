package openapi

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestCybotExclusiveBoundsCompatibility(t *testing.T) {
	for _, test := range []struct {
		name   string
		schema *openapi3.Schema
		want   float64
	}{
		{"inclusive minimum", openapi3.NewFloat64Schema().WithMin(1), 1},
		{"exclusive minimum", openapi3.NewFloat64Schema().WithMin(1).WithExclusiveMin(true), 2},
		{"exclusive maximum", openapi3.NewFloat64Schema().WithMax(-1).WithExclusiveMax(true), -2},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := openAPIExample(test.schema, map[*openapi3.Schema]*cachedSchema{})
			if err != nil || value != test.want {
				t.Fatalf("OpenAPI 3.0 bounds changed: got %v, %v; want %v", value, err, test.want)
			}
		})
	}
	for _, schema := range []*openapi3.Schema{
		openapi3.NewFloat64Schema().WithExclusiveMinValue(1),
		openapi3.NewFloat64Schema().WithExclusiveMaxValue(-1),
	} {
		if value, err := openAPIExample(schema, map[*openapi3.Schema]*cachedSchema{}); err != ErrNoExample || value != nil {
			t.Fatalf("unsupported OpenAPI 3.1 numeric bounds generated an unchecked example: %v, %v", value, err)
		}
	}
}

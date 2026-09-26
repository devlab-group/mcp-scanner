package fuzz

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/pkg/model"
)

func exampleTool() model.ToolInfo {
	return model.ToolInfo{
		Name: "read_file",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":  map[string]any{"type": "string"},
				"limit": map[string]any{"type": "integer"},
				"mode":  map[string]any{"type": "string", "enum": []any{"r", "w"}},
			},
			"required": []any{"path"},
		},
	}
}

func TestGenerateDeterministic(t *testing.T) {
	tool := exampleTool()
	a := Generate(tool, 42, Options{})
	b := Generate(tool, 42, Options{})
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("same seed produced different output:\na=%+v\nb=%+v", a, b)
	}

	c := Generate(tool, 43, Options{})
	if reflect.DeepEqual(a, c) {
		t.Fatalf("different seeds produced identical output")
	}
}

func TestGenerateRespectsRequiredAndEnum(t *testing.T) {
	tool := exampleTool()
	cases := Generate(tool, 1, Options{})
	if len(cases) == 0 {
		t.Fatalf("no cases generated")
	}
	for _, c := range cases {
		if _, ok := c.Arguments["path"]; !ok {
			t.Fatalf("required property 'path' missing in case %+v", c)
		}
		if c.Property != "mode" {
			if mode, ok := c.Arguments["mode"]; ok {
				if mode != "r" && mode != "w" {
					t.Fatalf("mode filler %v violates enum", mode)
				}
			}
		}
	}
}

func TestGenerateOnlyOnePropertyFuzzedPerCase(t *testing.T) {
	tool := exampleTool()
	cases := Generate(tool, 1, Options{})
	for _, c := range cases {
		got := c.Arguments[c.Property]
		if fmt.Sprint(got) != fmt.Sprint(c.Payload.Value) {
			t.Fatalf("case property %q does not carry its own payload: %+v", c.Property, c)
		}
	}
}

func TestEveryPayloadCarriesAMarker(t *testing.T) {
	tool := exampleTool()
	cases := Generate(tool, 7, Options{CanaryFiles: []CanaryFile{{ID: "aws-1", RelPath: ".aws/credentials"}}, CanaryHome: "/sandbox/home"})
	if len(cases) == 0 {
		t.Fatalf("no cases generated")
	}
	for _, c := range cases {
		if c.Payload.Marker == "" {
			t.Fatalf("payload without a marker: %+v", c)
		}
		if c.Payload.Class == ClassOversized {
			// A numeric overflow value cannot carry a text marker; the
			// marker still identifies the case for reproducibility
			continue
		}
		s := fmt.Sprint(c.Payload.Value)
		if !strings.Contains(s, c.Payload.Marker) {
			t.Fatalf("payload value does not embed its own marker: %+v", c)
		}
	}
}

func TestSchemalessToolStillProducesCases(t *testing.T) {
	tool := model.ToolInfo{Name: "anything"}
	cases := Generate(tool, 1, Options{})
	if len(cases) == 0 {
		t.Fatalf("expected a best-effort case for a schemaless tool")
	}
}

package server

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// openAPISpec returns the OpenAPI description as JSON, read from its source: the server serves the copy the web
// build bundles (web/dist/openapi.json), which go test does not need.
func openAPISpec(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../web/openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("openapi.yaml: %v", err)
	}
	raw, err := json.Marshal(stringKeys(doc))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// stringKeys turns mappings with non-string keys (an unquoted 200: response code decodes as an int) into
// map[string]any, which JSON can encode.
func stringKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = stringKeys(x)
		}
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = stringKeys(x)
		}
		return m
	case []any:
		for i, x := range t {
			t[i] = stringKeys(x)
		}
	}
	return v
}

var openAPIMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true,
	"head": true, "options": true, "trace": true}

// Every admin API route is described in the OpenAPI document, the document describes no route that does not exist,
// every path parameter is declared, and every reference resolves. The document is written by hand, so this checks
// what a generator would have guaranteed.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	raw := openAPISpec(t)
	var doc struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi version %q", doc.OpenAPI)
	}
	want := map[string]bool{"GET /api/openapi.json": true}
	for _, rt := range adminRouteList {
		want[rt.method+" "+rt.path] = true
	}
	got := map[string]bool{}
	params := regexp.MustCompile(`\{([^}]+)\}`)
	for path, item := range doc.Paths {
		var shared []json.RawMessage
		if p, ok := item["parameters"]; ok {
			_ = json.Unmarshal(p, &shared)
		}
		for method, op := range item {
			if !openAPIMethods[method] {
				continue
			}
			key := strings.ToUpper(method) + " " + path
			got[key] = true
			var o struct {
				OperationID string            `json:"operationId"`
				Parameters  []json.RawMessage `json:"parameters"`
				Responses   map[string]any    `json:"responses"`
			}
			if err := json.Unmarshal(op, &o); err != nil {
				t.Fatal(err)
			}
			if o.OperationID == "" || len(o.Responses) == 0 {
				t.Errorf("%s: needs an operationId and responses", key)
			}
			declared := map[string]bool{}
			for _, p := range append(slices.Clone(shared), o.Parameters...) {
				var pp struct {
					Ref  string `json:"$ref"`
					Name string `json:"name"`
					In   string `json:"in"`
				}
				_ = json.Unmarshal(p, &pp)
				if pp.Ref != "" {
					pp.Name = strings.ToLower(pp.Ref[strings.LastIndex(pp.Ref, "/")+1:])
					pp.In = "path"
				}
				if pp.In == "path" {
					declared[pp.Name] = true
				}
			}
			for _, m := range params.FindAllStringSubmatch(path, -1) {
				if !declared[m[1]] {
					t.Errorf("%s: path parameter %q is not declared", key, m[1])
				}
			}
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("route %s is not in the OpenAPI document", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("the OpenAPI document describes %s, which does not exist", k)
		}
	}
	// Every $ref points at something.
	var whole map[string]any
	_ = json.Unmarshal(raw, &whole)
	for _, ref := range regexp.MustCompile(`"\$ref":"#/([^"]+)"`).FindAllStringSubmatch(string(raw), -1) {
		var node any = whole
		for _, part := range strings.Split(ref[1], "/") {
			m, ok := node.(map[string]any)
			if !ok || m[part] == nil {
				t.Errorf("unresolved reference #/%s", ref[1])
				break
			}
			node = m[part]
		}
	}
}

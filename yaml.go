// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-ruby-hiera-eyaml/hiera-eyaml authors

package hieraeyaml

import (
	"fmt"

	"github.com/go-ruby-yaml/yaml"
)

// loadYAML decodes a YAML document through the Ruby-faithful go-ruby-yaml
// backend, the same one go-hiera uses for its built-in yaml_data backend.
func loadYAML(data []byte) (any, error) {
	return yaml.Load(string(data))
}

// topHash asserts that a decoded document is a mapping, as every Hiera data
// file must be. A nil document (empty YAML) is an empty hash.
func topHash(v any, path string) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: top level is not a mapping (got %T)", path, v)
	}
	return m, nil
}

// normalize converts a decoded value tree (which may hold go-ruby-yaml's
// *yaml.Map / yaml.Symbol) into the canonical model: map[string]any for hashes,
// []any for arrays, strings for symbols, scalars unchanged. It mirrors the
// normalisation go-hiera applies so eyaml data behaves identically to yaml_data.
func normalize(v any) any {
	switch x := v.(type) {
	case *yaml.Map:
		m := make(map[string]any, x.Len())
		for _, p := range x.Pairs() {
			m[keyString(p.Key)] = normalize(p.Val)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = normalize(val)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i := range x {
			s[i] = normalize(x[i])
		}
		return s
	case yaml.Symbol:
		return string(x)
	default:
		return v
	}
}

// keyString renders a decoded mapping key as the string Hiera keys always are.
func keyString(k any) string {
	switch s := k.(type) {
	case string:
		return s
	case yaml.Symbol:
		return string(s)
	default:
		return fmt.Sprintf("%v", k)
	}
}

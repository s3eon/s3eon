package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

type Interpolated[T any] struct {
	Value T
}

func (r *Interpolated[T]) UnmarshalYAML(value *yaml.Node) (err error) {
	if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
		return value.Decode(&r.Value)
	}

	node := &yaml.Node{
		Kind: yaml.ScalarNode,
		Tag:  yamlTagForType(r.Value),
	}

	v, idx, err := interpolate(value.Value, false)
	if err != nil {
		return fmt.Errorf("failed to interpolate at index %d: %w", idx, err)
	}

	node.Value = v
	return node.Decode(&r.Value)
}

func yamlTagForType(v any) string {
	t := reflect.TypeOf(v)
	if t == nil {
		return "!!null"
	}

	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	kind := t.Kind()
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "!!int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "!!int"
	case reflect.Float32, reflect.Float64:
		return "!!float"
	case reflect.Bool:
		return "!!bool"
	case reflect.String:
		return "!!str"
	default:
		return "!!str"
	}
}

func interpolate(src string, started bool) (_ string, idx int, err error) {
	var output strings.Builder
	runes := []rune(src)

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if started && r == '}' {
			// escaped }} inside ${...}
			if i+1 < len(runes) && runes[i+1] == '}' {
				output.WriteRune('}')
				i++
				continue
			}

			resolved, err := resolve(output.String())
			return resolved, i, err
		}

		if r != '$' {
			output.WriteRune(r)
			continue
		}

		// check for end of line
		if eol := i+1 >= len(runes); eol {
			output.WriteRune('$')
			break
		}

		next := runes[i+1]

		// Handle $${ -> ${
		if next == '$' {
			if i+2 < len(runes) && runes[i+2] == '{' {
				output.WriteString("${")
				i += 2
				continue
			}
			output.WriteString("$")
			continue
		}

		// Handle ${...}
		if next != '{' {
			output.WriteRune('$')
			continue
		}

		// Found ${...}
		start := i + 2
		var resolved string
		resolved, idx, err = interpolate(string(runes[start:]), true)
		if err != nil {
			return "", start + idx, err
		}
		output.WriteString(resolved)
		i = start + idx
	}

	return output.String(), idx, nil
}

func resolve(s string) (string, error) {
	switch {
	case strings.HasPrefix(s, "env://"):
		return os.Getenv(strings.TrimPrefix(string(s), "env://")), nil
	case strings.HasPrefix(s, "file://"):
		b, err := os.ReadFile(strings.TrimPrefix(string(s), "file://"))
		return string(b), err
	default:
		return "", fmt.Errorf("unsupported variable type")
	}
}

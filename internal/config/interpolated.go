package config

import (
	"bytes"
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

	node.Value, err = interpolate(value.Value)
	if err != nil {
		return err
	}

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

func interpolate(src string) (string, error) {
	var output strings.Builder
	runes := []rune(src)

	for i := 0; i < len(runes); i++ {
		r := runes[i]

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
			output.WriteRune(next)
			i++
			continue
		}

		// Found ${...}
		i += 2 // skip $ and {
		start := i
		depth := 1
		for i < len(runes) && depth > 0 {
			switch runes[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth > 0 {
				i++
			}
		}

		if depth != 0 {
			return "", fmt.Errorf("unterminated variable")
		}

		varName := string(runes[start:i])

		// recurse
		varName, err := interpolate(varName)
		if err != nil {
			return "", err
		}

		// resolve
		resolved, err := resolve([]byte(varName))
		if err != nil {
			return "", err
		}

		output.Write(resolved)
	}

	return output.String(), nil
}

func resolve(s []byte) ([]byte, error) {
	switch {
	case bytes.HasPrefix(s, []byte("env://")):
		return []byte(os.Getenv(strings.TrimPrefix(string(s), "env://"))), nil
	case bytes.HasPrefix(s, []byte("file://")):
		return os.ReadFile(strings.TrimPrefix(string(s), "file://"))
	default:
		return nil, fmt.Errorf("unsupported variable type")
	}
}

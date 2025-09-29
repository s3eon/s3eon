package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type MyConfig struct {
	User    Interpolated[string]    `yaml:"user"`
	Port    Interpolated[int]       `yaml:"port"`
	Number  Interpolated[int]       `yaml:"number"`
	Debug   Interpolated[bool]      `yaml:"debug"`
	Amount  Interpolated[MyFloat64] `yaml:"amount"`
	Secret  Interpolated[*MyString] `yaml:"secret"`
	Escaped Interpolated[string]    `yaml:"escaped"`
}

type MyFloat64 float64
type MyString string

func TestInterpolate(t *testing.T) {
	t.Setenv("PORT", "8080")
	t.Setenv("USER", "root")
	t.Setenv("VALID", "true")
	t.Setenv("FILENAME", "test")
	t.Setenv("AMOUNT", "1000.1")
	yamlData := `
user: ${env://USER}
port: ${env://PORT}
number: 0
amount: ${env://AMOUNT}
debug: ${env://VALID}
secret: ${file://./testdata/${env://FILENAME}.txt} ${file://./testdata/test{}.txt} test3
escaped: $${$$hello $$$${env://USER}}
`

	var cfg MyConfig
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))

	want := MyConfig{
		User:    Interpolated[string]{Value: "root"},
		Port:    Interpolated[int]{Value: 8080},
		Number:  Interpolated[int]{Value: 0},
		Debug:   Interpolated[bool]{Value: true},
		Amount:  Interpolated[MyFloat64]{Value: 1000.1},
		Secret:  Interpolated[*MyString]{Value: pointer(MyString("test test2 test3"))},
		Escaped: Interpolated[string]{Value: "${$$hello $$${env://USER}}"},
	}
	assert.Equal(t, want, cfg)
}

func pointer[T any](v T) *T {
	return &v
}

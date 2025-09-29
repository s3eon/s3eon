package s3proxy_test

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy(t *testing.T) {
	// Create a Rego query that references the "allow" rule
	r := rego.New(
		rego.Load([]string{"policy.rego"}, nil),
		rego.Query("data.authz.result"),
	)

	// Prepare the query for evaluation
	query, err := r.PrepareForEval(t.Context())
	require.NoError(t, err)

	req := map[string]interface{}{
		"action":   "Action",
		"endpoint": "endpoint.com",
		"bucket":   "bucket",
		"key":      "/some/path",
		"ip":       "192.168.0.1",
	}

	testdata := []struct {
		Scenario string
		Input    map[string]interface{}
		Result   bool
	}{
		{
			Scenario: "Default",
			Input: map[string]interface{}{
				"request": req,
				"allow":   []map[string]interface{}{},
				"deny":    []map[string]interface{}{},
			},
			Result: true,
		},
		{
			Scenario: "Allow Some Operation",
			Input: map[string]interface{}{
				"request": req,
				"allow": []map[string]interface{}{
					{
						"actions": []string{"Action", "Action1"},
						"buckets": []string{"bucket", "bucket1"},
					},
				},
				"deny": []map[string]interface{}{},
			},
			Result: true,
		},
		{
			Scenario: "Allow CIDR",
			Input: map[string]interface{}{
				"request": req,
				"allow": []map[string]interface{}{
					{
						"cidrs": []string{"192.168.0.0/24"},
					},
				},
				"deny": []map[string]interface{}{},
			},
			Result: true,
		},
		{
			Scenario: "Deny Not Match Bucket",
			Input: map[string]interface{}{
				"request": req,
				"allow": []map[string]interface{}{
					{
						"actions": []string{"Action"},
						"buckets": []string{"bucket2"},
					},
				},
				"deny": []map[string]interface{}{},
			},
			Result: false,
		},
		{
			Scenario: "Explicit Deny",
			Input: map[string]interface{}{
				"request": req,
				"allow":   []map[string]interface{}{},
				"deny": []map[string]interface{}{
					{
						"actions": []string{"Action"},
					},
				},
			},
			Result: false,
		},
		{
			Scenario: "Explicit Deny Not Match",
			Input: map[string]interface{}{
				"request": req,
				"allow":   []map[string]interface{}{},
				"deny": []map[string]interface{}{
					{
						"actions": []string{"Action1"},
					},
				},
			},
			Result: true,
		},
	}

	for _, tt := range testdata {
		t.Run(tt.Scenario, func(t *testing.T) {
			results, err := query.Eval(t.Context(), rego.EvalInput(tt.Input))
			require.NoError(t, err)

			require.Len(t, results, 1)
			require.IsType(t, results[0].Expressions[0].Value, true)
			assert.Equal(t, tt.Result, results[0].Expressions[0].Value)
		})
	}
}

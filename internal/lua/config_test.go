package lua

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestConfigService_Get(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	config := map[string]interface{}{
		"string_val": "hello",
		"int_val":    42,
		"float_val":  3.14,
		"bool_val":   true,
		"map_val": map[string]interface{}{
			"nested": "value",
		},
		"array_val": []interface{}{1, 2, 3},
	}

	service := NewConfigService(NewMapConfigSource(config))
	service.Register(L)

	tests := []struct {
		name     string
		script   string
		expected string
	}{
		{
			name:     "get string",
			script:   `return config.get("string_val")`,
			expected: "hello",
		},
		{
			name:     "get int",
			script:   `return tostring(config.get("int_val"))`,
			expected: "42",
		},
		{
			name:     "get float",
			script:   `return tostring(config.get("float_val"))`,
			expected: "3.14",
		},
		{
			name:     "get bool",
			script:   `return tostring(config.get("bool_val"))`,
			expected: "true",
		},
		{
			name:     "get nested value",
			script:   `return config.get("map_val").nested`,
			expected: "value",
		},
		{
			name:     "get array element",
			script:   `return tostring(config.get("array_val")[1])`,
			expected: "1",
		},
		{
			name:     "get missing with default",
			script:   `return config.get("missing", "default")`,
			expected: "default",
		},
		{
			name:     "get missing without default",
			script:   `local val = config.get("missing"); return (val == nil) and "nil" or "not-nil"`,
			expected: "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := L.DoString(tt.script); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			result := L.Get(-1)
			L.Pop(1)

			got := lua.LVAsString(result)
			if got != tt.expected {
				t.Errorf("get() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConfigService_Has(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	config := map[string]interface{}{
		"existing": "value",
	}

	service := NewConfigService(NewMapConfigSource(config))
	service.Register(L)

	tests := []struct {
		name     string
		script   string
		expected bool
	}{
		{
			name:     "has existing key",
			script:   `return config.has("existing")`,
			expected: true,
		},
		{
			name:     "has missing key",
			script:   `return config.has("missing")`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := L.DoString(tt.script); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			result := L.Get(-1)
			L.Pop(1)

			if result.Type() != lua.LTBool {
				t.Fatalf("expected bool result, got %s", result.Type())
			}

			got := lua.LVAsBool(result)
			if got != tt.expected {
				t.Errorf("has() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfigService_Keys(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	config := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	service := NewConfigService(NewMapConfigSource(config))
	service.Register(L)

	script := `
		local keys = config.keys()
		local count = 0
		for i, key in ipairs(keys) do
			count = count + 1
		end
		return count
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	if result.Type() != lua.LTNumber {
		t.Fatalf("expected number result, got %s", result.Type())
	}

	count := int(lua.LVAsNumber(result))
	if count != 3 {
		t.Errorf("keys() returned %d keys, want 3", count)
	}
}

func TestConfigService_EmptyConfig(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	service := NewConfigService(nil)
	service.Register(L)

	script := `
		local val = config.get("anything")
		return (val == nil) and "nil" or "not-nil"
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	if lua.LVAsString(result) != "nil" {
		t.Errorf("expected nil for empty config")
	}
}

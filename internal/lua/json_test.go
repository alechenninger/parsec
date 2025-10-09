package lua

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestJSONService_Encode(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	service := NewJSONService()
	service.Register(L)

	tests := []struct {
		name     string
		script   string
		expected string
	}{
		{
			name:     "encode object",
			script:   `return json.encode({key = "value", num = 42})`,
			expected: `{"key":"value","num":42}`,
		},
		{
			name:     "encode array",
			script:   `return json.encode({1, 2, 3})`,
			expected: `[1,2,3]`,
		},
		{
			name:     "encode string",
			script:   `return json.encode("hello")`,
			expected: `"hello"`,
		},
		{
			name:     "encode number",
			script:   `return json.encode(42)`,
			expected: `42`,
		},
		{
			name:     "encode boolean",
			script:   `return json.encode(true)`,
			expected: `true`,
		},
		{
			name:     "encode null",
			script:   `return json.encode(nil)`,
			expected: `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := L.DoString(tt.script); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			result := L.Get(-1)
			L.Pop(1)

			if result.Type() != lua.LTString {
				t.Fatalf("expected string result, got %s", result.Type())
			}

			got := lua.LVAsString(result)
			if got != tt.expected {
				t.Errorf("encode() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestJSONService_Decode(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	service := NewJSONService()
	service.Register(L)

	tests := []struct {
		name   string
		json   string
		check  string
		expect string
	}{
		{
			name:   "decode object",
			json:   `{"key":"value","num":42}`,
			check:  `local obj = json.decode('{"key":"value","num":42}'); return obj.key .. ":" .. obj.num`,
			expect: "value:42",
		},
		{
			name:   "decode array",
			json:   `[1,2,3]`,
			check:  `local arr = json.decode('[1,2,3]'); return arr[1] .. "," .. arr[2] .. "," .. arr[3]`,
			expect: "1,2,3",
		},
		{
			name:   "decode string",
			json:   `"hello"`,
			check:  `return json.decode('"hello"')`,
			expect: "hello",
		},
		{
			name:   "decode number",
			json:   `42`,
			check:  `return tostring(json.decode('42'))`,
			expect: "42",
		},
		{
			name:   "decode boolean",
			json:   `true`,
			check:  `return tostring(json.decode('true'))`,
			expect: "true",
		},
		{
			name:   "decode null",
			json:   `null`,
			check:  `local val = json.decode('null'); return (val == nil) and "nil" or "not-nil"`,
			expect: "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := L.DoString(tt.check); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			result := L.Get(-1)
			L.Pop(1)

			got := lua.LVAsString(result)
			if got != tt.expect {
				t.Errorf("decode result = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestJSONService_DecodeError(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	service := NewJSONService()
	service.Register(L)

	script := `
		local result, err = json.decode('invalid json {{{')
		if result == nil and err ~= nil then
			return "error"
		end
		return "no-error"
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	if lua.LVAsString(result) != "error" {
		t.Errorf("expected decode to return error for invalid JSON")
	}
}

func TestJSONService_RoundTrip(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	service := NewJSONService()
	service.Register(L)

	script := `
		local obj = {
			name = "Alice",
			age = 30,
			roles = {"admin", "user"},
			settings = {
				theme = "dark",
				notifications = true
			}
		}
		
		local jsonStr = json.encode(obj)
		local decoded = json.decode(jsonStr)
		
		return decoded.name .. ":" .. decoded.age .. ":" .. decoded.roles[1] .. ":" .. decoded.settings.theme
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	expected := "Alice:30:admin:dark"
	if got := lua.LVAsString(result); got != expected {
		t.Errorf("round trip result = %q, want %q", got, expected)
	}
}

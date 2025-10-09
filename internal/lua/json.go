package lua

import (
	"encoding/json"
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

// JSONService provides JSON encoding/decoding functionality to Lua scripts
type JSONService struct{}

// NewJSONService creates a new JSON service
func NewJSONService() *JSONService {
	return &JSONService{}
}

// Register adds the JSON service to the Lua state
// Usage in Lua:
//
//	local obj = json.decode('{"key": "value"}')
//	local str = json.encode({key = "value"})
func (s *JSONService) Register(L *lua.LState) {
	// Create JSON module table
	mod := L.NewTable()

	// Register functions
	L.SetField(mod, "encode", L.NewFunction(s.luaJSONEncode))
	L.SetField(mod, "decode", L.NewFunction(s.luaJSONDecode))

	// Set the module as a global
	L.SetGlobal("json", mod)
}

// luaJSONEncode encodes a Lua value to JSON string
// Args: value (any)
// Returns: json_string or (nil, error)
func (s *JSONService) luaJSONEncode(L *lua.LState) int {
	value := L.Get(1)

	goValue := LuaToGo(value)
	jsonBytes, err := json.Marshal(goValue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("failed to encode JSON: %v", err)))
		return 2
	}

	L.Push(lua.LString(string(jsonBytes)))
	return 1
}

// luaJSONDecode decodes a JSON string to a Lua value
// Args: json_string (string)
// Returns: value or (nil, error)
func (s *JSONService) luaJSONDecode(L *lua.LState) int {
	jsonStr := L.CheckString(1)

	var goValue interface{}
	err := json.Unmarshal([]byte(jsonStr), &goValue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("failed to decode JSON: %v", err)))
		return 2
	}

	L.Push(GoToLua(L, goValue))
	return 1
}

// LuaToGo converts a Lua value to a Go value
func LuaToGo(lv lua.LValue) interface{} {
	switch v := lv.(type) {
	case *lua.LNilType:
		return nil
	case lua.LBool:
		return bool(v)
	case lua.LString:
		return string(v)
	case lua.LNumber:
		return float64(v)
	case *lua.LTable:
		// Check if it's an array or object
		maxn := v.MaxN()
		if maxn > 0 {
			// Array
			arr := make([]interface{}, 0, maxn)
			for i := 1; i <= maxn; i++ {
				arr = append(arr, LuaToGo(v.RawGetInt(i)))
			}
			return arr
		} else {
			// Object
			obj := make(map[string]interface{})
			v.ForEach(func(key, value lua.LValue) {
				if key.Type() == lua.LTString {
					obj[key.String()] = LuaToGo(value)
				}
			})
			return obj
		}
	default:
		return nil
	}
}

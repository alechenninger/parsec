package lua

import (
	lua "github.com/yuin/gopher-lua"
)

// ConfigSource is an interface for retrieving configuration values
// Implementations can back this with environment variables, config files, etc.
type ConfigSource interface {
	// Get retrieves a configuration value by key
	// Returns the value and true if found, or nil and false if not found
	Get(key string) (any, bool)

	// Keys returns all available configuration keys
	Keys() []string
}

// MapConfigSource is a simple in-memory implementation of ConfigSource
type MapConfigSource struct {
	values map[string]any
}

// NewMapConfigSource creates a ConfigSource backed by a map
func NewMapConfigSource(values map[string]any) ConfigSource {
	if values == nil {
		values = make(map[string]any)
	}
	return &MapConfigSource{values: values}
}

// Get retrieves a value from the map
func (m *MapConfigSource) Get(key string) (any, bool) {
	val, ok := m.values[key]
	return val, ok
}

// Keys returns all keys in the map
func (m *MapConfigSource) Keys() []string {
	keys := make([]string, 0, len(m.values))
	for k := range m.values {
		keys = append(keys, k)
	}
	return keys
}

// ConfigService provides access to configuration values in Lua scripts
type ConfigService struct {
	source ConfigSource
}

// NewConfigService creates a new config service with the given configuration source
func NewConfigService(source ConfigSource) *ConfigService {
	if source == nil {
		source = NewMapConfigSource(nil)
	}
	return &ConfigService{
		source: source,
	}
}

// Register adds the config service to the Lua state
// Usage in Lua:
//
//	local value = config.get("key")
//	local value = config.get("key", "default_value")
//	local exists = config.has("key")
func (s *ConfigService) Register(L *lua.LState) {
	// Create config module table
	mod := L.NewTable()

	// Register functions
	L.SetField(mod, "get", L.NewFunction(s.luaConfigGet))
	L.SetField(mod, "has", L.NewFunction(s.luaConfigHas))
	L.SetField(mod, "keys", L.NewFunction(s.luaConfigKeys))

	// Set the module as a global
	L.SetGlobal("config", mod)
}

// luaConfigGet retrieves a configuration value
// Args: key (string), [default (any)]
// Returns: value or default if not found
func (s *ConfigService) luaConfigGet(L *lua.LState) int {
	key := L.CheckString(1)
	defaultValue := L.Get(2)

	if value, ok := s.source.Get(key); ok {
		L.Push(GoToLua(L, value))
	} else if defaultValue != lua.LNil {
		L.Push(defaultValue)
	} else {
		L.Push(lua.LNil)
	}

	return 1
}

// luaConfigHas checks if a configuration key exists
// Args: key (string)
// Returns: bool
func (s *ConfigService) luaConfigHas(L *lua.LState) int {
	key := L.CheckString(1)
	_, ok := s.source.Get(key)
	L.Push(lua.LBool(ok))
	return 1
}

// luaConfigKeys returns all configuration keys
// Returns: table (array of strings)
func (s *ConfigService) luaConfigKeys(L *lua.LState) int {
	tbl := L.NewTable()
	keys := s.source.Keys()
	for i, key := range keys {
		tbl.RawSetInt(i+1, lua.LString(key))
	}
	L.Push(tbl)
	return 1
}

// GoToLua converts a Go value to a Lua value
func GoToLua(L *lua.LState, value any) lua.LValue {
	if value == nil {
		return lua.LNil
	}

	switch v := value.(type) {
	case string:
		return lua.LString(v)
	case int:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case float64:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	case map[string]any:
		tbl := L.NewTable()
		for key, val := range v {
			L.SetField(tbl, key, GoToLua(L, val))
		}
		return tbl
	case []any:
		tbl := L.NewTable()
		for i, val := range v {
			tbl.RawSetInt(i+1, GoToLua(L, val))
		}
		return tbl
	default:
		// For unsupported types, return nil
		return lua.LNil
	}
}

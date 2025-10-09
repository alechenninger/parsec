# HTTP Fixtures

This directory contains example HTTP fixture files for testing Lua data sources and other HTTP-based functionality.

## File Formats

Fixtures can be defined in either YAML or JSON format:

- **YAML**: `.yaml` or `.yml` extension (more human-readable)
- **JSON**: `.json` extension (better for programmatic generation)

## Fixture Structure

### YAML Format

```yaml
fixtures:
  - request:
      method: GET                          # HTTP method (GET, POST, etc.) or "*" for any
      url: https://api.example.com/data    # URL to match
      url_type: exact                      # "exact" or "pattern" (regex)
      headers:                             # Optional: headers to match
        Authorization: Bearer token
    response:
      status: 200                          # HTTP status code
      headers:                             # Optional: response headers
        Content-Type: application/json
      body: '{"data": "value"}'            # Response body
      delay: 100ms                         # Optional: delay before responding
```

### JSON Format

```json
{
  "fixtures": [
    {
      "request": {
        "method": "GET",
        "url": "https://api.example.com/data",
        "url_type": "exact",
        "headers": {
          "Authorization": "Bearer token"
        }
      },
      "response": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": "{\"data\": \"value\"}"
      }
    }
  ]
}
```

## Matching Rules

Fixtures are matched in order, with the first matching fixture being used:

1. **Method Matching**: Exact match or `"*"` for any method
2. **URL Matching**:
   - `url_type: exact` - Exact string match
   - `url_type: pattern` - Regular expression match
3. **Header Matching** (optional): All specified headers must match exactly

## Usage Examples

### In Tests

```go
provider, err := httpfixture.LoadFixturesFromFile("test/fixtures/user_api.yaml")
if err != nil {
    t.Fatal(err)
}

ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
    Name:   "user-data",
    Script: script,
    HTTPConfig: &lua.HTTPServiceConfig{
        Timeout:         30 * time.Second,
        FixtureProvider: provider,
    },
})
```

### Loading Multiple Files

```go
provider, err := httpfixture.LoadFixturesFromDir("test/fixtures")
if err != nil {
    t.Fatal(err)
}
```

This loads all `.json`, `.yaml`, and `.yml` files from the directory.

## Example Files

- **`user_api.yaml`** - User API fixtures with various matching patterns
- **`data_api.json`** - Data API fixtures in JSON format

## Tips

1. **Order Matters**: Place more specific patterns before generic ones
2. **Use Patterns**: Regex patterns allow flexible matching (e.g., `/user/\d+` matches any numeric user ID)
3. **Test Locally**: Fixtures enable fast, hermetic testing without external dependencies
4. **Realism**: Keep fixture responses realistic to catch integration issues early


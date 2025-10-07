package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"
)

// FormMarshaler implements runtime.Marshaler for application/x-www-form-urlencoded
// This is needed for RFC 8693 OAuth 2.0 Token Exchange compatibility
type FormMarshaler struct {
	jsonMarshaler runtime.Marshaler
}

// NewFormMarshaler creates a new form marshaler
func NewFormMarshaler() *FormMarshaler {
	return &FormMarshaler{
		jsonMarshaler: &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		},
	}
}

// ContentType returns the content type for this marshaler
func (m *FormMarshaler) ContentType(_ any) string {
	return "application/x-www-form-urlencoded"
}

// Marshal converts a proto message to form-urlencoded format
// Note: This is used for responses, which should still be JSON for our use case
func (m *FormMarshaler) Marshal(v any) ([]byte, error) {
	// For responses, we want JSON not form-encoded
	// Only requests come in as form-encoded
	return m.jsonMarshaler.Marshal(v)
}

// Unmarshal converts form-urlencoded data to a proto message
func (m *FormMarshaler) Unmarshal(data []byte, v any) error {
	// Parse the form data
	values, err := url.ParseQuery(string(data))
	if err != nil {
		return fmt.Errorf("failed to parse form data: %w", err)
	}

	// Convert to a flat map for easier handling
	dataMap := make(map[string]any)
	for key, vals := range values {
		if len(vals) == 1 {
			dataMap[key] = vals[0]
		} else if len(vals) > 1 {
			dataMap[key] = vals
		}
	}

	// Convert map to JSON, then use protojson to unmarshal
	// This is a bridge since proto unmarshaling expects structured data
	jsonData, err := json.Marshal(dataMap)
	if err != nil {
		return fmt.Errorf("failed to marshal intermediate JSON: %w", err)
	}

	return m.jsonMarshaler.Unmarshal(jsonData, v)
}

// NewDecoder creates a decoder for form-urlencoded data
func (m *FormMarshaler) NewDecoder(r io.Reader) runtime.Decoder {
	return &formDecoder{reader: r, marshaler: m}
}

// NewEncoder creates an encoder (returns JSON encoder for responses)
func (m *FormMarshaler) NewEncoder(w io.Writer) runtime.Encoder {
	return m.jsonMarshaler.NewEncoder(w)
}

// formDecoder implements runtime.Decoder for form data
type formDecoder struct {
	reader    io.Reader
	marshaler *FormMarshaler
}

// Decode reads form-urlencoded data and decodes it into v
func (d *formDecoder) Decode(v any) error {
	data, err := io.ReadAll(d.reader)
	if err != nil {
		return fmt.Errorf("failed to read form data: %w", err)
	}

	return d.marshaler.Unmarshal(data, v)
}

// Delimiter is not used for form encoding
func (m *FormMarshaler) Delimiter() []byte {
	return []byte("\n")
}

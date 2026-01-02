package donut

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatBinary(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	result, err := FormatOutput(data, DONUT_FORMAT_BINARY)
	if err != nil {
		t.Fatalf("FormatOutput(BINARY) failed: %v", err)
	}

	if !bytes.Equal(result, data) {
		t.Errorf("Binary format changed data: got %v, expected %v", result, data)
	}
}

func TestFormatBase64(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	result, err := FormatOutput(data, DONUT_FORMAT_BASE64)
	if err != nil {
		t.Fatalf("FormatOutput(BASE64) failed: %v", err)
	}

	// Base64 of DEADBEEF should be "3q2+7w=="
	expected := "3q2+7w=="
	if string(result) != expected {
		t.Errorf("Base64 format: got %s, expected %s", string(result), expected)
	}
}

func TestFormatC(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	result, err := FormatOutput(data, DONUT_FORMAT_C)
	if err != nil {
		t.Fatalf("FormatOutput(C) failed: %v", err)
	}

	str := string(result)
	// Should contain hex bytes
	if !strings.Contains(str, "0xde") && !strings.Contains(str, "0xDE") {
		t.Error("C format missing hex bytes")
	}
	if !strings.Contains(str, "0xad") && !strings.Contains(str, "0xAD") {
		t.Error("C format missing hex bytes")
	}
}

func TestFormatRuby(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	result, err := FormatOutput(data, DONUT_FORMAT_RUBY)
	if err != nil {
		t.Fatalf("FormatOutput(RUBY) failed: %v", err)
	}

	str := string(result)
	// Ruby format uses \xNN escapes
	if !strings.Contains(str, "\\xde") && !strings.Contains(str, "\\xDE") {
		t.Errorf("Ruby format missing escape sequences: %s", str)
	}
}

func TestFormatPython(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	result, err := FormatOutput(data, DONUT_FORMAT_PYTHON)
	if err != nil {
		t.Fatalf("FormatOutput(PYTHON) failed: %v", err)
	}

	str := string(result)
	// Python format uses \xNN escapes
	if !strings.Contains(str, "\\xde") && !strings.Contains(str, "\\xDE") {
		t.Errorf("Python format missing escape sequences: %s", str)
	}
}

func TestFormatPowerShell(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	result, err := FormatOutput(data, DONUT_FORMAT_POWERSHELL)
	if err != nil {
		t.Fatalf("FormatOutput(POWERSHELL) failed: %v", err)
	}

	str := string(result)
	// PowerShell uses 0xNN format
	if !strings.Contains(str, "0xde") && !strings.Contains(str, "0xDE") {
		t.Errorf("PowerShell format missing hex: %s", str)
	}
}

func TestFormatCSharp(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	result, err := FormatOutput(data, DONUT_FORMAT_CSHARP)
	if err != nil {
		t.Fatalf("FormatOutput(CSHARP) failed: %v", err)
	}

	str := string(result)
	// C# uses 0xNN format
	if !strings.Contains(str, "0xde") && !strings.Contains(str, "0xDE") {
		t.Errorf("C# format missing hex: %s", str)
	}
}

func TestFormatHex(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	result, err := FormatOutput(data, DONUT_FORMAT_HEX)
	if err != nil {
		t.Fatalf("FormatOutput(HEX) failed: %v", err)
	}

	expected := "deadbeef"
	if strings.ToLower(string(result)) != expected {
		t.Errorf("Hex format: got %s, expected %s", string(result), expected)
	}
}

func TestFormatUUID(t *testing.T) {
	// UUID format needs at least 16 bytes
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	result, err := FormatOutput(data, DONUT_FORMAT_UUID)
	if err != nil {
		t.Fatalf("FormatOutput(UUID) failed: %v", err)
	}

	str := string(result)
	// UUID format should contain dashes and curly braces
	if !strings.Contains(str, "-") {
		t.Errorf("UUID format missing dashes: %s", str)
	}
}

func TestFormatInvalid(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	result, err := FormatOutput(data, 999)
	// The implementation may return binary format for unknown format types
	// rather than returning an error
	if err != nil {
		// This is acceptable behavior
		return
	}
	// If no error, some data should be returned
	if len(result) == 0 {
		t.Error("FormatOutput returned empty for valid input")
	}
}

func TestFormatEmptyData(t *testing.T) {
	// Test all formats with empty data
	formats := []int{
		DONUT_FORMAT_BINARY,
		DONUT_FORMAT_BASE64,
		DONUT_FORMAT_C,
		DONUT_FORMAT_RUBY,
		DONUT_FORMAT_PYTHON,
		DONUT_FORMAT_POWERSHELL,
		DONUT_FORMAT_CSHARP,
		DONUT_FORMAT_HEX,
	}

	for _, format := range formats {
		_, err := FormatOutput([]byte{}, format)
		if err != nil {
			t.Errorf("FormatOutput(%d) failed on empty data: %v", format, err)
		}
	}
}

package donut

import (
	"bytes"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	// Test generating random bytes
	b1, err := RandomBytes(16)
	if err != nil {
		t.Fatalf("RandomBytes failed: %v", err)
	}
	if len(b1) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(b1))
	}

	// Ensure randomness (different each time)
	b2, _ := RandomBytes(16)
	if bytes.Equal(b1, b2) {
		t.Error("RandomBytes returned identical values")
	}

	// Test zero length
	b0, err := RandomBytes(0)
	if err != nil {
		t.Fatalf("RandomBytes(0) failed: %v", err)
	}
	if len(b0) != 0 {
		t.Errorf("Expected 0 bytes, got %d", len(b0))
	}
}

func TestPackUint32(t *testing.T) {
	tests := []struct {
		input    uint32
		expected []byte
	}{
		{0x00000000, []byte{0x00, 0x00, 0x00, 0x00}},
		{0x01020304, []byte{0x04, 0x03, 0x02, 0x01}}, // Little-endian
		{0xDEADBEEF, []byte{0xEF, 0xBE, 0xAD, 0xDE}},
		{0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range tests {
		result := PackUint32(tc.input)
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("PackUint32(0x%08X) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestPackUint64(t *testing.T) {
	tests := []struct {
		input    uint64
		expected []byte
	}{
		{0x0000000000000000, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{0x0102030405060708, []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}},
		{0xDEADBEEFCAFEBABE, []byte{0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE}},
	}

	for _, tc := range tests {
		result := PackUint64(tc.input)
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("PackUint64(0x%016X) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestToUnicode(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"A", []byte{0x41, 0x00}},
		{"AB", []byte{0x41, 0x00, 0x42, 0x00}},
		{"", []byte{}},
	}

	for _, tc := range tests {
		result := ToUnicode(tc.input)
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("ToUnicode(%q) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestPadBytes(t *testing.T) {
	tests := []struct {
		input     []byte
		alignment int
		expected  int // expected length
	}{
		{[]byte{1, 2, 3}, 4, 4},
		{[]byte{1, 2, 3, 4}, 4, 4},
		{[]byte{1, 2, 3, 4, 5}, 4, 8},
		{[]byte{1}, 16, 16},
		{[]byte{}, 16, 0},
		{make([]byte, 16), 16, 16},
		{make([]byte, 17), 16, 32},
	}

	for _, tc := range tests {
		result := PadBytes(tc.input, tc.alignment)
		if len(result) != tc.expected {
			t.Errorf("PadBytes(%d bytes, align %d) = %d bytes, expected %d",
				len(tc.input), tc.alignment, len(result), tc.expected)
		}
		// Verify original data is preserved
		if len(tc.input) > 0 && !bytes.HasPrefix(result, tc.input) {
			t.Error("PadBytes did not preserve original data")
		}
	}
}

func TestROTR64(t *testing.T) {
	tests := []struct {
		v        uint64
		n        uint
		expected uint64
	}{
		{0x8000000000000000, 1, 0x4000000000000000},
		{0x0000000000000001, 1, 0x8000000000000000},
		{0xDEADBEEFCAFEBABE, 0, 0xDEADBEEFCAFEBABE},
		{0xDEADBEEFCAFEBABE, 64, 0xDEADBEEFCAFEBABE},
	}

	for _, tc := range tests {
		result := ROTR64(tc.v, tc.n)
		if result != tc.expected {
			t.Errorf("ROTR64(0x%016X, %d) = 0x%016X, expected 0x%016X",
				tc.v, tc.n, result, tc.expected)
		}
	}
}

func TestROTR32(t *testing.T) {
	tests := []struct {
		v        uint32
		n        uint
		expected uint32
	}{
		{0x80000000, 1, 0x40000000},
		{0x00000001, 1, 0x80000000},
		{0xDEADBEEF, 0, 0xDEADBEEF},
		{0xDEADBEEF, 32, 0xDEADBEEF},
	}

	for _, tc := range tests {
		result := ROTR32(tc.v, tc.n)
		if result != tc.expected {
			t.Errorf("ROTR32(0x%08X, %d) = 0x%08X, expected 0x%08X",
				tc.v, tc.n, result, tc.expected)
		}
	}
}

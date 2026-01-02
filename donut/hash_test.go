package donut

import (
	"testing"
)

func TestMaru(t *testing.T) {
	// Test that Maru produces consistent results
	iv := uint64(0x12345678DEADBEEF)
	input1 := []byte("kernel32.dll")

	hash1 := Maru(input1, iv)
	hash2 := Maru(input1, iv)

	if hash1 != hash2 {
		t.Errorf("Maru not deterministic: %016X != %016X", hash1, hash2)
	}

	// Different inputs should produce different hashes
	hash3 := Maru([]byte("ntdll.dll"), iv)
	if hash1 == hash3 {
		t.Error("Maru collision: different inputs produced same hash")
	}

	// Hash should be non-zero for valid input
	if hash1 == 0 {
		t.Error("Maru returned zero for valid input")
	}
}

func TestMaruStr(t *testing.T) {
	iv := uint64(0x12345678DEADBEEF)

	hash1 := MaruStr("kernel32.dll", iv)
	hash2 := Maru([]byte("kernel32.dll"), iv)

	if hash1 != hash2 {
		t.Errorf("MaruStr != Maru: %016X != %016X", hash1, hash2)
	}
}

func TestAPIHash(t *testing.T) {
	iv := uint64(0xDEADBEEF)

	tests := []struct {
		dll string
		api string
	}{
		{"kernel32.dll", "LoadLibraryA"},
		{"kernel32.dll", "GetProcAddress"},
		{"ntdll.dll", "NtAllocateVirtualMemory"},
		{"ole32.dll", "CoInitializeEx"},
	}

	hashes := make(map[uint64]string)
	for _, tc := range tests {
		hash := APIHash(tc.dll, tc.api, iv)
		name := tc.dll + "!" + tc.api

		// Check for collisions
		if existing, ok := hashes[hash]; ok {
			t.Errorf("Hash collision: %s and %s both hash to %016X", existing, name, hash)
		}
		hashes[hash] = name

		// Hash should be non-zero
		if hash == 0 {
			t.Errorf("APIHash(%s, %s) returned zero", tc.dll, tc.api)
		}

		// Hash should be deterministic
		hash2 := APIHash(tc.dll, tc.api, iv)
		if hash != hash2 {
			t.Errorf("APIHash not deterministic for %s", name)
		}
	}
}

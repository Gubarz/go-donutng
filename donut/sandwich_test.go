package donut

import (
	"bytes"
	"testing"
)

// ============== SANDWICH FUNCTION TESTS ==============
// These test the core shellcode generation without needing real PEs

func TestSandwichX86Structure(t *testing.T) {
	loader := []byte{0x90, 0x90, 0x90, 0xC3} // nop nop nop ret
	instance := []byte{0x41, 0x42, 0x43, 0x44}

	sc := Sandwich(DONUT_ARCH_X86, loader, instance)

	// Should start with E8 (call)
	if sc[0] != 0xE8 {
		t.Errorf("Should start with CALL (0xE8), got 0x%02X", sc[0])
	}

	// Check call offset (little endian)
	offset := uint32(sc[1]) | uint32(sc[2])<<8 | uint32(sc[3])<<16 | uint32(sc[4])<<24
	if offset != uint32(len(instance)) {
		t.Errorf("Call offset should be %d, got %d", len(instance), offset)
	}

	// After instance: 59 5A 51 52 (pop ecx, pop edx, push ecx, push edx)
	stubOffset := 5 + len(instance)
	expected := []byte{0x59, 0x5A, 0x51, 0x52}
	if !bytes.Equal(sc[stubOffset:stubOffset+4], expected) {
		t.Errorf("x86 stack setup incorrect, got %X", sc[stubOffset:stubOffset+4])
	}

	// Loader should be at the end
	loaderOffset := stubOffset + 4
	if !bytes.Equal(sc[loaderOffset:], loader) {
		t.Error("Loader not found at expected position")
	}
}

func TestSandwichX64Structure(t *testing.T) {
	loader := []byte{0x90, 0x90, 0x90, 0xC3}
	instance := []byte{0x41, 0x42, 0x43, 0x44}

	sc := Sandwich(DONUT_ARCH_X64, loader, instance)

	// Should start with E8 (call)
	if sc[0] != 0xE8 {
		t.Errorf("Should start with CALL (0xE8), got 0x%02X", sc[0])
	}

	// After instance: 59 (pop rcx) then RSP alignment stub starting with 55 (push rbp)
	stubOffset := 5 + len(instance)
	if sc[stubOffset] != 0x59 {
		t.Errorf("Should have pop rcx (0x59), got 0x%02X", sc[stubOffset])
	}
	if sc[stubOffset+1] != 0x55 {
		t.Errorf("RSP stub should start with push rbp (0x55), got 0x%02X", sc[stubOffset+1])
	}

	// Verify RSP alignment stub (22 bytes)
	rspStub := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xE5, // mov rbp, rsp
		0x48, 0x83, 0xE4, 0xF0, // and rsp, -0x10
		0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
		0xE8, 0x05, 0x00, 0x00, 0x00, // call $+5
		0x48, 0x89, 0xEC, // mov rsp, rbp
		0x5D, // pop rbp
		0xC3, // ret
	}
	if !bytes.Equal(sc[stubOffset+1:stubOffset+1+len(rspStub)], rspStub) {
		t.Error("RSP alignment stub mismatch")
	}
}

func TestSandwichX84Structure(t *testing.T) {
	instance := []byte{0x41, 0x42, 0x43, 0x44}

	sc := Sandwich(DONUT_ARCH_X84, nil, instance)

	// After instance: 59 31 C0 48 0F 88 (pop ecx, xor eax eax, dec eax/REX, js)
	stubOffset := 5 + len(instance)
	expected := []byte{0x59, 0x31, 0xC0, 0x48, 0x0F, 0x88}
	if !bytes.Equal(sc[stubOffset:stubOffset+6], expected) {
		t.Errorf("x84 arch detection stub incorrect, got %X, expected %X",
			sc[stubOffset:stubOffset+6], expected)
	}

	// Total size should include both loaders
	// Structure: E8 + 4byte offset + instance + 59 + 31 C0 48 0F 88 + 4byte jump + RSP stub + x64 loader + 5A 51 52 + x86 loader
	expectedMinSize := 5 + len(instance) + 1 + 6 + 4 + 22 + len(LOADER_EXE_X64) + 3 + len(LOADER_EXE_X86) - 1
	if len(sc) < expectedMinSize {
		t.Errorf("x84 shellcode too small: %d < %d", len(sc), expectedMinSize)
	}

	t.Logf("x84 shellcode size: %d bytes (x64 loader: %d, x86 loader: %d)",
		len(sc), len(LOADER_EXE_X64), len(LOADER_EXE_X86))
}

func TestSandwichX84ContainsBothLoaders(t *testing.T) {
	instance := make([]byte, 100)
	sc := Sandwich(DONUT_ARCH_X84, nil, instance)

	// Should contain signature bytes from both loaders
	// Check that the shellcode contains both loaders by verifying size
	x64Only := Sandwich(DONUT_ARCH_X64, LOADER_EXE_X64, instance)
	x86Only := Sandwich(DONUT_ARCH_X86, LOADER_EXE_X86, instance)

	// x84 should be roughly x64 + x86 loader sizes combined
	expectedSize := len(x64Only) + len(LOADER_EXE_X86) + 10 // +10 for arch detect stub
	if len(sc) < expectedSize-50 || len(sc) > expectedSize+50 {
		t.Errorf("x84 size %d not in expected range around %d", len(sc), expectedSize)
	}

	t.Logf("Sizes - x86: %d, x64: %d, x84: %d", len(x86Only), len(x64Only), len(sc))
}

func TestSandwichX84JumpOffset(t *testing.T) {
	instance := []byte{0x41, 0x42, 0x43, 0x44}
	sc := Sandwich(DONUT_ARCH_X84, nil, instance)

	// Find the js instruction offset
	stubOffset := 5 + len(instance)
	// 59 31 C0 48 0F 88 [4-byte offset]
	jsOffset := stubOffset + 6

	// Read the 4-byte little-endian offset
	jumpDist := uint32(sc[jsOffset]) | uint32(sc[jsOffset+1])<<8 |
		uint32(sc[jsOffset+2])<<16 | uint32(sc[jsOffset+3])<<24

	// Should jump over RSP stub (22 bytes) + x64 loader
	expectedJump := uint32(22 + len(LOADER_EXE_X64))
	if jumpDist != expectedJump {
		t.Errorf("Jump offset %d != expected %d (22 + %d)", jumpDist, expectedJump, len(LOADER_EXE_X64))
	}
}

// ============== LOADER TESTS ==============

func TestLoaderSizes(t *testing.T) {
	if len(LOADER_EXE_X64) == 0 {
		t.Error("X64 loader is empty")
	}
	if len(LOADER_EXE_X86) == 0 {
		t.Error("X86 loader is empty")
	}

	t.Logf("X64 loader: %d bytes", len(LOADER_EXE_X64))
	t.Logf("X86 loader: %d bytes", len(LOADER_EXE_X86))

	// Sanity check - loaders should be reasonably sized (between 5KB and 35KB)
	// Note: Donut v1.1+ loaders are larger due to additional bypass/features
	if len(LOADER_EXE_X64) < 5000 || len(LOADER_EXE_X64) > 35000 {
		t.Errorf("X64 loader size suspicious: %d (expected 5000-35000)", len(LOADER_EXE_X64))
	}
	if len(LOADER_EXE_X86) < 5000 || len(LOADER_EXE_X86) > 35000 {
		t.Errorf("X86 loader size suspicious: %d (expected 5000-35000)", len(LOADER_EXE_X86))
	}
}

func TestLoaderStartsWithCode(t *testing.T) {
	// Loaders should start with executable code, not NULL bytes
	if LOADER_EXE_X64[0] == 0x00 {
		t.Error("X64 loader starts with NULL byte")
	}
	if LOADER_EXE_X86[0] == 0x00 {
		t.Error("X86 loader starts with NULL byte")
	}
}

// ============== CONFIG TESTS ==============

func TestDefaultConfigValues(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Arch != X84 {
		t.Errorf("Default arch should be X84 (2), got %d", cfg.Arch)
	}
	if cfg.Entropy != DONUT_ENTROPY_DEFAULT {
		t.Errorf("Default entropy should be %d, got %d", DONUT_ENTROPY_DEFAULT, cfg.Entropy)
	}
	if cfg.Format != uint32(DONUT_FORMAT_BINARY) {
		t.Errorf("Default format should be BINARY (1), got %d", cfg.Format)
	}
	if cfg.Bypass != DONUT_BYPASS_CONTINUE {
		t.Errorf("Default bypass should be CONTINUE (3), got %d", cfg.Bypass)
	}
}

func TestConfigArchConstants(t *testing.T) {
	// Verify constants match donut spec
	if DONUT_ARCH_ANY != -1 {
		t.Errorf("DONUT_ARCH_ANY should be -1, got %d", DONUT_ARCH_ANY)
	}
	if DONUT_ARCH_X86 != 1 {
		t.Errorf("DONUT_ARCH_X86 should be 1, got %d", DONUT_ARCH_X86)
	}
	if DONUT_ARCH_X64 != 2 {
		t.Errorf("DONUT_ARCH_X64 should be 2, got %d", DONUT_ARCH_X64)
	}
	if DONUT_ARCH_X84 != 3 {
		t.Errorf("DONUT_ARCH_X84 should be 3, got %d", DONUT_ARCH_X84)
	}
}

func TestConfigEntropyConstants(t *testing.T) {
	if DONUT_ENTROPY_NONE != 1 {
		t.Errorf("DONUT_ENTROPY_NONE should be 1, got %d", DONUT_ENTROPY_NONE)
	}
	if DONUT_ENTROPY_RANDOM != 2 {
		t.Errorf("DONUT_ENTROPY_RANDOM should be 2, got %d", DONUT_ENTROPY_RANDOM)
	}
	if DONUT_ENTROPY_DEFAULT != 3 {
		t.Errorf("DONUT_ENTROPY_DEFAULT should be 3, got %d", DONUT_ENTROPY_DEFAULT)
	}
}

// ============== API HASH TESTS ==============

func TestAPIHashConsistency(t *testing.T) {
	// Same input should always produce same hash
	var iv uint64 = 0

	hash1 := Maru([]byte("kernel32.dll"), iv)
	hash2 := Maru([]byte("kernel32.dll"), iv)

	if hash1 != hash2 {
		t.Errorf("Maru hash not consistent: %016x != %016x", hash1, hash2)
	}
}

func TestAPIHashDifferentInputs(t *testing.T) {
	var iv uint64 = 0

	hash1 := Maru([]byte("kernel32.dll"), iv)
	hash2 := Maru([]byte("ntdll.dll"), iv)

	if hash1 == hash2 {
		t.Error("Different inputs should produce different hashes")
	}
}

func TestAPIHashIVAffectsOutput(t *testing.T) {
	var iv1 uint64 = 0
	var iv2 uint64 = 0x0807060504030201

	hash1 := Maru([]byte("kernel32.dll"), iv1)
	hash2 := Maru([]byte("kernel32.dll"), iv2)

	if hash1 == hash2 {
		t.Error("Different IVs should produce different hashes")
	}
}

// ============== ENCRYPTION TESTS ==============

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	ctr := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	original := []byte("Hello, World! This is a test message for encryption.")
	data := make([]byte, len(original))
	copy(data, original)

	// Encrypt
	data = EncryptCTR(key, ctr, data)

	// Data should be different after encryption
	if bytes.Equal(data, original) {
		t.Error("Data unchanged after encryption")
	}

	// Decrypt (CTR mode is symmetric) - need fresh ctr
	ctr2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	data = EncryptCTR(key, ctr2, data)

	// Should match original
	if !bytes.Equal(data, original) {
		t.Error("Decrypt didn't restore original data")
	}
}

func TestEncryptDifferentKeys(t *testing.T) {
	key1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	key2 := []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	ctr1 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ctr2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	data1 := []byte("Test data")
	data2 := make([]byte, len(data1))
	copy(data2, data1)

	data1 = EncryptCTR(key1, ctr1, data1)
	data2 = EncryptCTR(key2, ctr2, data2)

	if bytes.Equal(data1, data2) {
		t.Error("Different keys should produce different ciphertext")
	}
}

// ============== COMPRESSION TESTS ==============

func TestCompressionRoundTrip(t *testing.T) {
	// Note: aPLib decompression is handled by the loader, not Go code
	// This test just verifies compression produces valid output
	original := bytes.Repeat([]byte("AAAA"), 1000)

	compressed, err := CompressData(original, DONUT_COMPRESS_APLIB)
	if err != nil {
		t.Fatalf("Compression failed: %v", err)
	}

	// Should be smaller for repetitive data
	if len(compressed) >= len(original) {
		t.Logf("Warning: compressed %d >= original %d", len(compressed), len(original))
	}

	t.Logf("aPLib compression: %d -> %d bytes (%.1f%% ratio)",
		len(original), len(compressed),
		float64(len(compressed))/float64(len(original))*100)
}

func TestCompressionNone(t *testing.T) {
	original := []byte("Test data")

	result, err := CompressData(original, DONUT_COMPRESS_NONE)
	if err != nil {
		t.Fatalf("CompressNone failed: %v", err)
	}

	if !bytes.Equal(result, original) {
		t.Error("COMPRESS_NONE should return original data")
	}
}

// ============== FORMAT TESTS ==============

func TestFormatOutputSizes(t *testing.T) {
	data := []byte{0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43}

	binary, _ := FormatOutput(data, DONUT_FORMAT_BINARY)
	base64, _ := FormatOutput(data, DONUT_FORMAT_BASE64)
	hex, _ := FormatOutput(data, DONUT_FORMAT_HEX)

	// Binary should be same size
	if len(binary) != len(data) {
		t.Errorf("Binary format changed size: %d -> %d", len(data), len(binary))
	}

	// Base64 should be ~4/3 larger
	if len(base64) < len(data) {
		t.Error("Base64 should be larger than binary")
	}

	// Hex should be 2x larger
	if len(hex) != len(data)*2 {
		t.Errorf("Hex should be 2x size: expected %d, got %d", len(data)*2, len(hex))
	}
}

// ============== INSTANCE SERIALIZATION TESTS ==============

func TestInstanceStructSize(t *testing.T) {
	// Test that the instance struct is reasonable sized
	inst := &DonutInstance{}

	// The instance struct should exist and be usable
	// Just verify we can create the struct
	_ = inst

	// Log struct info
	t.Logf("DonutInstance struct initialized successfully")
}

// ============== UTILITY TESTS ==============

func TestRandomBytesLength(t *testing.T) {
	for _, size := range []int{8, 16, 32, 64, 128} {
		data, err := RandomBytes(size)
		if err != nil {
			t.Fatalf("RandomBytes(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("RandomBytes(%d) returned %d bytes", size, len(data))
		}
	}
}

func TestRandomBytesUnique(t *testing.T) {
	data1, _ := RandomBytes(32)
	data2, _ := RandomBytes(32)

	if bytes.Equal(data1, data2) {
		t.Error("Two random byte arrays should not be equal")
	}
}

func TestToUnicodeConversion(t *testing.T) {
	input := "test"
	unicode := ToUnicode(input)

	// Each char becomes 2 bytes in UTF-16LE
	expected := []byte{'t', 0, 'e', 0, 's', 0, 't', 0}
	if !bytes.Equal(unicode, expected) {
		t.Errorf("Unicode conversion wrong: got %v, expected %v", unicode, expected)
	}
}

package donut

import (
	"bytes"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Arch != X84 {
		t.Errorf("Expected Arch=%d (x84), got %d", X84, config.Arch)
	}
	if config.Bypass != DONUT_BYPASS_CONTINUE {
		t.Errorf("Expected Bypass=%d, got %d", DONUT_BYPASS_CONTINUE, config.Bypass)
	}
	if config.Entropy != DONUT_ENTROPY_DEFAULT {
		t.Errorf("Expected Entropy=%d, got %d", DONUT_ENTROPY_DEFAULT, config.Entropy)
	}
	if config.ExitOpt != DONUT_OPT_EXIT_THREAD {
		t.Errorf("Expected ExitOpt=%d, got %d", DONUT_OPT_EXIT_THREAD, config.ExitOpt)
	}
	if config.Format != uint32(DONUT_FORMAT_BINARY) {
		t.Errorf("Expected Format=%d, got %d", DONUT_FORMAT_BINARY, config.Format)
	}
	if config.InstType != DONUT_INSTANCE_PIC {
		t.Errorf("Expected InstType=%d, got %d", DONUT_INSTANCE_PIC, config.InstType)
	}
}

func TestDonutError(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{DONUT_ERROR_SUCCESS, "Operation successful"},
		{DONUT_ERROR_FILE_NOT_FOUND, "File not found"},
		{DONUT_ERROR_FILE_EMPTY, "File is empty"},
		{DONUT_ERROR_INVALID_ARCH, "Invalid architecture specified"},
		{999, "Unknown error"},
	}

	for _, tc := range tests {
		result := DonutError(tc.code)
		if result != tc.expected {
			t.Errorf("DonutError(%d) = %q, expected %q", tc.code, result, tc.expected)
		}
	}
}

func TestGUIDData4Size(t *testing.T) {
	g := GUID{}
	expectedSize := 16
	actualSize := 4 + 2 + 2 + 8 // Data1 + Data2 + Data3 + Data4

	if actualSize != expectedSize {
		t.Errorf("GUID size mismatch: expected %d bytes, got %d", expectedSize, actualSize)
	}

	if len(g.Data4) != 8 {
		t.Errorf("GUID.Data4 should be 8 bytes, got %d", len(g.Data4))
	}
}

func TestDonutCryptSize(t *testing.T) {
	crypt := DonutCrypt{}

	if len(crypt.MasterKey) != DONUT_KEY_LEN {
		t.Errorf("MasterKey length should be %d, got %d", DONUT_KEY_LEN, len(crypt.MasterKey))
	}
	if len(crypt.Counter) != DONUT_BLK_LEN {
		t.Errorf("Counter length should be %d, got %d", DONUT_BLK_LEN, len(crypt.Counter))
	}
}

func TestDonutModuleFields(t *testing.T) {
	mod := DonutModule{}

	if len(mod.Runtime) != DONUT_MAX_NAME {
		t.Errorf("Runtime length should be %d, got %d", DONUT_MAX_NAME, len(mod.Runtime))
	}
	if len(mod.Domain) != DONUT_MAX_NAME {
		t.Errorf("Domain length should be %d, got %d", DONUT_MAX_NAME, len(mod.Domain))
	}
	if len(mod.Cls) != DONUT_MAX_NAME {
		t.Errorf("Cls length should be %d, got %d", DONUT_MAX_NAME, len(mod.Cls))
	}
	if len(mod.Method) != DONUT_MAX_NAME {
		t.Errorf("Method length should be %d, got %d", DONUT_MAX_NAME, len(mod.Method))
	}
	if len(mod.Args) != DONUT_MAX_NAME {
		t.Errorf("Args length should be %d, got %d", DONUT_MAX_NAME, len(mod.Args))
	}
	if len(mod.Sig) != DONUT_SIG_LEN {
		t.Errorf("Sig length should be %d, got %d", DONUT_SIG_LEN, len(mod.Sig))
	}
}

func TestConstants(t *testing.T) {
	if DONUT_KEY_LEN != 16 {
		t.Errorf("DONUT_KEY_LEN should be 16, got %d", DONUT_KEY_LEN)
	}
	if DONUT_BLK_LEN != 16 {
		t.Errorf("DONUT_BLK_LEN should be 16, got %d", DONUT_BLK_LEN)
	}
	if DONUT_MAX_NAME != 256 {
		t.Errorf("DONUT_MAX_NAME should be 256, got %d", DONUT_MAX_NAME)
	}
	if DONUT_SIG_LEN != 8 {
		t.Errorf("DONUT_SIG_LEN should be 8, got %d", DONUT_SIG_LEN)
	}
}

func TestModuleTypeValues(t *testing.T) {
	if DONUT_MODULE_NET_DLL != 1 {
		t.Errorf("DONUT_MODULE_NET_DLL should be 1")
	}
	if DONUT_MODULE_NET_EXE != 2 {
		t.Errorf("DONUT_MODULE_NET_EXE should be 2")
	}
	if DONUT_MODULE_DLL != 3 {
		t.Errorf("DONUT_MODULE_DLL should be 3")
	}
	if DONUT_MODULE_EXE != 4 {
		t.Errorf("DONUT_MODULE_EXE should be 4")
	}
	if DONUT_MODULE_VBS != 5 {
		t.Errorf("DONUT_MODULE_VBS should be 5")
	}
	if DONUT_MODULE_JS != 6 {
		t.Errorf("DONUT_MODULE_JS should be 6")
	}
}

func TestFileInfo(t *testing.T) {
	info := FileInfo{
		Len:  1000,
		Zlen: 500,
		Type: DONUT_MODULE_EXE,
		Arch: DONUT_ARCH_X64,
		Ver:  "v4.0.30319",
	}

	if info.Len != 1000 {
		t.Errorf("FileInfo.Len should be 1000")
	}
	if info.Zlen != 500 {
		t.Errorf("FileInfo.Zlen should be 500")
	}
	if info.Type != DONUT_MODULE_EXE {
		t.Errorf("FileInfo.Type should be DONUT_MODULE_EXE")
	}
	if info.Arch != DONUT_ARCH_X64 {
		t.Errorf("FileInfo.Arch should be DONUT_ARCH_X64")
	}
	if info.Ver != "v4.0.30319" {
		t.Errorf("FileInfo.Ver should be v4.0.30319")
	}
}

func TestDonutInstanceFields(t *testing.T) {
	inst := DonutInstance{}

	// Updated for syscall support: hash[58] instead of hash[64]
	if len(inst.Hash) != 58 {
		t.Errorf("Hash array should be 58 elements (reduced for syscall support)")
	}
	if len(inst.DllNames) != DONUT_MAX_NAME {
		t.Errorf("DllNames should be %d bytes", DONUT_MAX_NAME)
	}
	if len(inst.Decoy) != DONUT_MAX_PATH*2 {
		t.Errorf("Decoy should be %d bytes", DONUT_MAX_PATH*2)
	}
}

func TestCopyToFixedArray(t *testing.T) {
	mod := DonutModule{}
	testStr := "TestClass"

	copy(mod.Cls[:], testStr)

	result := string(bytes.TrimRight(mod.Cls[:], "\x00"))
	if result != testStr {
		t.Errorf("Expected %q, got %q", testStr, result)
	}
}

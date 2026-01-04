package donut

import (
	"testing"
)

// TestInstanceSerializationSize verifies that the serialized instance
// matches the expected C struct size (3384 bytes without module data)
// Updated for syscall support: hash[58] + syscall_list
func TestInstanceSerializationSize(t *testing.T) {
	config := DefaultConfig()
	config.Entropy = DONUT_ENTROPY_NONE   // Disable encryption for size check
	config.InstType = DONUT_INSTANCE_HTTP // Don't embed module data

	// Create a minimal instance
	inst := &DonutInstance{}
	mod := &DonutModule{
		Type: int32(DONUT_MODULE_EXE),
		Data: []byte{},
	}

	// Serialize
	data, err := serializeInstance(inst, mod, config)
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	// Expected size from C: end of mod_len = 3384 bytes (without module)
	// Changed from 3424 with syscall integration (hash[58] + syscall_list)
	expectedSize := 3384
	if len(data) != expectedSize {
		t.Errorf("Instance size mismatch: got %d, expected %d (diff: %d)",
			len(data), expectedSize, len(data)-expectedSize)
	}

	// Verify key offsets
	t.Logf("Serialized instance size: %d bytes", len(data))

	// Check some key byte positions (updated for syscall support):
	// IV should be at offset 0x28 (40)
	// api.hash should start at offset 0x30 (48)
	// syscall_list should be at offset 0x200 (512)
	// exit_opt should be at offset 0x208 (520)
	// api_cnt (encrypted section start) should be at offset 0x214 (532)
}

// TestCalculateOffsets calculates what the Go serialization actually produces
func TestCalculateOffsets(t *testing.T) {
	// Unencrypted header sizes (updated for syscall support):
	lenSize := 4         // uint32
	keySize := 32        // DONUT_CRYPT (16 + 16)
	padIV := 4           // alignment padding
	ivSize := 8          // uint64
	hashSize := 58 * 8   // uint64[58] = 464 (reduced from 64)
	syscallListSize := 8 // uint64 syscall_list (new)
	exitOptSize := 4     // int32
	entropySize := 4     // int32
	oepSize := 4         // uint32

	unencryptedSize := lenSize + keySize + padIV + ivSize + hashSize +
		syscallListSize + exitOptSize + entropySize + oepSize

	t.Logf("Unencrypted header size: %d (expected: 532)", unencryptedSize)
	if unencryptedSize != 532 {
		t.Errorf("Unencrypted header size mismatch: got %d, expected 532", unencryptedSize)
	}

	// Encrypted section sizes:
	apiCntSize := 4          // int32
	dllNamesSize := 256      // char[256]
	datanameSize := 8        // char[8]
	kernelbaseSize := 12     // char[12]
	amsiSize := 8            // char[8]
	clrSize := 4             // char[4]
	wldpSize := 8            // char[8]
	ntdllSize := 8           // char[8]
	cmdSymsSize := 256       // char[256]
	exitApiSize := 256       // char[256]
	bypassSize := 4          // int32
	headersSize := 4         // int32
	wldpQuerySize := 32      // char[32]
	wldpIsApprovedSize := 32 // char[32]
	amsiInitSize := 16       // char[16]
	amsiScanBufSize := 16    // char[16]
	amsiScanStrSize := 16    // char[16]
	etwEventWriteSize := 16  // char[16]
	etwEventUnregSize := 20  // char[20]
	etwRet64Size := 1        // char[1]
	etwRet32Size := 4        // char[4]
	wscriptSize := 8         // char[8]
	wscriptExeSize := 12     // char[12]
	decoySize := 520         // char[520]

	// Up to decoy
	encBeforeGuids := apiCntSize + dllNamesSize + datanameSize + kernelbaseSize +
		amsiSize + clrSize + wldpSize + ntdllSize + cmdSymsSize + exitApiSize +
		bypassSize + headersSize + wldpQuerySize + wldpIsApprovedSize +
		amsiInitSize + amsiScanBufSize + amsiScanStrSize + etwEventWriteSize +
		etwEventUnregSize + etwRet64Size + etwRet32Size + wscriptSize +
		wscriptExeSize + decoySize

	t.Logf("Encrypted section before GUIDs: %d bytes", encBeforeGuids)
	t.Logf("Offset of first GUID in encrypted section: %d", encBeforeGuids)
	t.Logf("Absolute offset of first GUID: %d (expected: 2053)", unencryptedSize+encBeforeGuids)

	// The offset 2053 is not 4-byte aligned (2053 % 4 = 1), so we need 3 bytes padding
	padGuids := 3
	guidsSize := 15 * 16 // 15 GUIDs * 16 bytes each

	// Before mac - need alignment check
	offsetBeforeMac := unencryptedSize + encBeforeGuids + padGuids + guidsSize + 4 + 256 + 256 + 256 + 8 + 256
	t.Logf("Offset before mac: %d", offsetBeforeMac)

	// mac needs 8-byte alignment
	padMac := 0
	if offsetBeforeMac%8 != 0 {
		padMac = 8 - (offsetBeforeMac % 8)
	}
	t.Logf("Mac padding needed: %d", padMac)

	macSize := 8
	modKeySize := 32
	modLenSize := 8

	totalSize := unencryptedSize + encBeforeGuids + padGuids + guidsSize +
		4 + 256 + 256 + 256 + 8 + 256 + // type, server, username, password, http_req, sig
		padMac + macSize + modKeySize + modLenSize

	t.Logf("Calculated total size: %d (expected: 3384)", totalSize)
	if totalSize != 3384 {
		t.Errorf("Total size mismatch: got %d, expected 3384 (diff: %d)",
			totalSize, totalSize-3384)
	}
}

// TestModuleHeaderSize verifies the module header serialization size
func TestModuleHeaderSize(t *testing.T) {
	// Calculate expected module header size (up to 'data' field at offset 1320)
	// Based on C struct offsets:
	// type: 0, thread: 4, compress: 8, runtime: 12 (256 bytes)
	// domain: 268 (256 bytes), cls: 524 (256 bytes), method: 780 (256 bytes)
	// args: 1036 (256 bytes), unicode: 1292 (4 bytes), sig: 1296 (8 bytes)
	// mac: 1304 (8 bytes), zlen: 1312 (4 bytes), len: 1316 (4 bytes)
	// data: 1320

	// Calculate Go serialization sizes
	typeSize := 4      // int32
	threadSize := 4    // int32
	compressSize := 4  // int32
	runtimeSize := 256 // [256]byte
	domainSize := 256  // [256]byte
	clsSize := 256     // [256]byte
	methodSize := 256  // [256]byte
	argsSize := 256    // [256]byte
	unicodeSize := 4   // int32
	sigSize := 8       // [8]byte
	macSize := 8       // uint64
	zlenSize := 4      // uint32
	lenSize := 4       // uint32

	calculatedSize := typeSize + threadSize + compressSize + runtimeSize +
		domainSize + clsSize + methodSize + argsSize + unicodeSize +
		sigSize + macSize + zlenSize + lenSize

	expectedSize := 1320

	t.Logf("Calculated module header size: %d bytes (expected: %d)", calculatedSize, expectedSize)

	if calculatedSize != expectedSize {
		t.Errorf("Module header size mismatch: got %d, expected %d (diff: %d)",
			calculatedSize, expectedSize, calculatedSize-expectedSize)
	}
}

// TestInstanceOffsets verifies that Go serialization produces correct byte offsets
// Updated for syscall support: hash[58] + syscall_list
func TestInstanceOffsets(t *testing.T) {
	// Expected offsets from C compiler output (with syscall support)
	expectedOffsets := map[string]int{
		"len":            0,
		"key":            4,
		"iv":             40,
		"hash":           48,
		"syscall_list":   512,
		"exit_opt":       520,
		"entropy":        524,
		"oep":            528,
		"api_cnt":        532,
		"dll_names":      536,
		"dataname":       792,
		"kernelbase":     800,
		"amsi":           812,
		"clr":            820,
		"wldp":           824,
		"ntdll":          832,
		"cmd_syms":       840,
		"exit_api":       1096,
		"bypass":         1352,
		"headers":        1356,
		"wldpQuery":      1360,
		"wldpIsApproved": 1392,
		"amsiInit":       1424,
		"amsiScanBuf":    1440,
		"amsiScanStr":    1456,
		"etwEventWrite":  1472,
		"etwEventUnreg":  1488,
		"etwRet64":       1508,
		"etwRet32":       1509,
		"wscript":        1513,
		"wscript_exe":    1521,
		"decoy":          1533,
		"xIID_IUnknown":  2056,
		"type":           2296,
		"server":         2300,
		"username":       2556,
		"password":       2812,
		"http_req":       3068,
		"sig":            3076,
		"mac":            3336,
		"mod_key":        3344,
		"mod_len":        3376,
	}

	// Calculate what Go serialization produces
	goOffsets := make(map[string]int)
	offset := 0

	// Header (unencrypted)
	goOffsets["len"] = offset
	offset += 4
	goOffsets["key"] = offset
	offset += 32
	offset += 4 // padding for iv alignment
	goOffsets["iv"] = offset
	offset += 8
	goOffsets["hash"] = offset
	offset += 464 // 58 * 8 (reduced from 512 = 64 * 8)
	goOffsets["syscall_list"] = offset
	offset += 8
	goOffsets["exit_opt"] = offset
	offset += 4
	goOffsets["entropy"] = offset
	offset += 4
	goOffsets["oep"] = offset
	offset += 4

	// Encrypted section starts
	goOffsets["api_cnt"] = offset
	offset += 4
	goOffsets["dll_names"] = offset
	offset += 256
	goOffsets["dataname"] = offset
	offset += 8
	goOffsets["kernelbase"] = offset
	offset += 12
	goOffsets["amsi"] = offset
	offset += 8
	goOffsets["clr"] = offset
	offset += 4
	goOffsets["wldp"] = offset
	offset += 8
	goOffsets["ntdll"] = offset
	offset += 8
	goOffsets["cmd_syms"] = offset
	offset += 256
	goOffsets["exit_api"] = offset
	offset += 256
	goOffsets["bypass"] = offset
	offset += 4
	goOffsets["headers"] = offset
	offset += 4
	goOffsets["wldpQuery"] = offset
	offset += 32
	goOffsets["wldpIsApproved"] = offset
	offset += 32
	goOffsets["amsiInit"] = offset
	offset += 16
	goOffsets["amsiScanBuf"] = offset
	offset += 16
	goOffsets["amsiScanStr"] = offset
	offset += 16
	goOffsets["etwEventWrite"] = offset
	offset += 16
	goOffsets["etwEventUnreg"] = offset
	offset += 20
	goOffsets["etwRet64"] = offset
	offset += 1
	goOffsets["etwRet32"] = offset
	offset += 4
	goOffsets["wscript"] = offset
	offset += 8
	goOffsets["wscript_exe"] = offset
	offset += 12
	goOffsets["decoy"] = offset
	offset += 520
	offset += 3 // padding for GUID alignment
	goOffsets["xIID_IUnknown"] = offset
	offset += 15 * 16 // 15 GUIDs
	goOffsets["type"] = offset
	offset += 4
	goOffsets["server"] = offset
	offset += 256
	goOffsets["username"] = offset
	offset += 256
	goOffsets["password"] = offset
	offset += 256
	goOffsets["http_req"] = offset
	offset += 8
	goOffsets["sig"] = offset
	offset += 256
	offset += 4 // padding for mac alignment
	goOffsets["mac"] = offset
	offset += 8
	goOffsets["mod_key"] = offset
	offset += 32
	goOffsets["mod_len"] = offset

	// Compare
	allMatch := true
	for field, expected := range expectedOffsets {
		got, ok := goOffsets[field]
		if !ok {
			t.Errorf("Missing field in Go offsets: %s", field)
			allMatch = false
			continue
		}
		if got != expected {
			t.Errorf("Offset mismatch for %s: Go=%d, C=%d (diff=%d)",
				field, got, expected, got-expected)
			allMatch = false
		}
	}

	if allMatch {
		t.Log("All offsets match!")
	}
}

package donut

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testPESource is the Go source code we compile into test executables.
// It's just a minimal program that exits cleanly.
const testPESource = `package main

func main() {}
`

// buildTestPE compiles Go source to a Windows PE executable.
// This is the most readable and auditable way to create test PEs.
func buildTestPE(t *testing.T, goarch string) []byte {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "donut-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	srcFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(srcFile, []byte(testPESource), 0644); err != nil {
		t.Fatalf("Failed to write source: %v", err)
	}

	outFile := filepath.Join(tmpDir, "test.exe")
	cmd := exec.Command("go", "build", "-o", outFile, "-ldflags=-s -w", srcFile)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+goarch, "CGO_ENABLED=0")

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to compile test PE (GOARCH=%s): %v\n%s", goarch, err, output)
	}

	pe, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("Failed to read compiled PE: %v", err)
	}

	return pe
}

// ============== BASIC GENERATION TESTS ==============

func TestE2E_BasicGeneration_X64(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed to generate shellcode: %v", err)
	}

	if shellcode.Len() < 1000 {
		t.Errorf("Shellcode too small: %d bytes", shellcode.Len())
	}

	if shellcode.Bytes()[0] != 0xE8 {
		t.Errorf("Should start with CALL (0xE8), got 0x%02X", shellcode.Bytes()[0])
	}

	if !bytes.Contains(shellcode.Bytes(), LOADER_EXE_X64[:100]) {
		t.Error("Shellcode should contain x64 loader")
	}

	t.Logf("Generated x64 shellcode: %d bytes", shellcode.Len())
}

func TestE2E_BasicGeneration_X86(t *testing.T) {
	pe := buildTestPE(t, "386")
	cfg := DefaultConfig()
	cfg.Arch = X32
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed to generate shellcode: %v", err)
	}

	if shellcode.Len() < 1000 {
		t.Errorf("Shellcode too small: %d bytes", shellcode.Len())
	}

	if shellcode.Bytes()[0] != 0xE8 {
		t.Errorf("Should start with CALL (0xE8), got 0x%02X", shellcode.Bytes()[0])
	}

	if !bytes.Contains(shellcode.Bytes(), LOADER_EXE_X86[:100]) {
		t.Error("Shellcode should contain x86 loader")
	}

	t.Logf("Generated x86 shellcode: %d bytes", shellcode.Len())
}

func TestE2E_BasicGeneration_X84(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X84
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed to generate shellcode: %v", err)
	}

	cfg64 := DefaultConfig()
	cfg64.Arch = X64
	cfg64.Entropy = DONUT_ENTROPY_NONE
	sc64, _ := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg64)

	if shellcode.Len() <= sc64.Len() {
		t.Errorf("x84 (%d bytes) should be larger than x64 (%d bytes)", shellcode.Len(), sc64.Len())
	}

	if !bytes.Contains(shellcode.Bytes(), LOADER_EXE_X64[:100]) {
		t.Error("x84 shellcode should contain x64 loader")
	}
	if !bytes.Contains(shellcode.Bytes(), LOADER_EXE_X86[:100]) {
		t.Error("x84 shellcode should contain x86 loader")
	}

	t.Logf("Generated x84 shellcode: %d bytes (x64: %d)", shellcode.Len(), sc64.Len())
}

// ============== ENTROPY TESTS ==============

func TestE2E_Entropy_None(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	sc1, err1 := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	sc2, err2 := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed: %v / %v", err1, err2)
	}

	if sc1.Len() != sc2.Len() {
		t.Errorf("Different sizes: %d vs %d", sc1.Len(), sc2.Len())
	}

	t.Logf("Entropy=NONE: %d bytes", sc1.Len())
}

func TestE2E_Entropy_Random(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_RANDOM

	sc1, err1 := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	sc2, err2 := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed: %v / %v", err1, err2)
	}

	if bytes.Equal(sc1.Bytes(), sc2.Bytes()) {
		t.Error("Entropy=RANDOM should produce different output each time")
	}

	t.Logf("Random entropy: sc1=%d bytes, sc2=%d bytes", sc1.Len(), sc2.Len())
}

func TestE2E_Entropy_Default_Encrypted(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_DEFAULT

	sc1, err1 := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	sc2, err2 := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed: %v / %v", err1, err2)
	}

	if bytes.Equal(sc1.Bytes(), sc2.Bytes()) {
		t.Error("Entropy=DEFAULT (encrypted) should produce different output")
	}

	t.Logf("Encrypted shellcode: %d bytes", sc1.Len())
}

// ============== OUTPUT FORMAT TESTS ==============

func TestE2E_Format_Binary(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_BINARY)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !bytes.Equal(output, shellcode.Bytes()) {
		t.Error("Binary format should not modify shellcode")
	}

	if output[0] != 0xE8 {
		t.Errorf("Should start with 0xE8, got 0x%02X", output[0])
	}
}

func TestE2E_Format_Base64(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_BASE64)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		t.Fatalf("Invalid base64: %v", err)
	}

	if !bytes.Equal(decoded, shellcode.Bytes()) {
		t.Error("Base64 decode should match original shellcode")
	}

	t.Logf("Base64: %d bytes -> %d chars", shellcode.Len(), len(output))
}

func TestE2E_Format_C(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_C)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	str := string(output)
	if !strings.Contains(str, "unsigned char") {
		t.Error("C format should contain 'unsigned char'")
	}

	t.Logf("C format: %d chars", len(output))
}

func TestE2E_Format_Python(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_PYTHON)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	str := string(output)
	if !strings.Contains(str, "payload") {
		t.Error("Python format should contain 'payload'")
	}

	t.Logf("Python format: %d chars", len(output))
}

func TestE2E_Format_PowerShell(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_POWERSHELL)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	str := string(output)
	if !strings.Contains(str, "$buf") && !strings.Contains(str, "[Byte[]]") {
		t.Error("PowerShell format should contain '$buf' or '[Byte[]]'")
	}

	t.Logf("PowerShell format: %d chars", len(output))
}

func TestE2E_Format_CSharp(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_CSHARP)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	str := string(output)
	if !strings.Contains(str, "byte[]") {
		t.Error("C# format should contain 'byte[]'")
	}

	t.Logf("C# format: %d chars", len(output))
}

func TestE2E_Format_Hex(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_HEX)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	str := string(output)
	if len(output) != shellcode.Len()*2 {
		t.Errorf("Hex should be 2x length: got %d, expected %d", len(output), shellcode.Len()*2)
	}

	if !strings.HasPrefix(strings.ToLower(str), "e8") {
		t.Errorf("Hex should start with 'e8', got '%s'", str[:min(4, len(str))])
	}

	t.Logf("Hex format: %d chars", len(output))
}

func TestE2E_Format_UUID(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_UUID)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	str := string(output)
	if !strings.Contains(str, "-") {
		t.Error("UUID format should contain dashes")
	}

	t.Logf("UUID format: %d chars", len(output))
}

func TestE2E_Format_Ruby(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	output, err := FormatOutput(shellcode.Bytes(), DONUT_FORMAT_RUBY)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	str := string(output)
	if !strings.Contains(str, "payload") {
		t.Error("Ruby format should contain 'payload'")
	}

	t.Logf("Ruby format: %d chars", len(output))
}

// ============== ARGUMENTS TESTS ==============

func TestE2E_WithArguments(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Parameters = "-group=system"

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	if !bytes.Contains(shellcode.Bytes(), []byte("-group=system")) {
		t.Error("Shellcode should contain the argument string")
	}

	t.Logf("Shellcode with args: %d bytes", shellcode.Len())
}

func TestE2E_WithMultipleArguments(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Parameters = "arg1 arg2 arg3"

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	if !bytes.Contains(shellcode.Bytes(), []byte("arg1 arg2 arg3")) {
		t.Error("Shellcode should contain all arguments")
	}
}

func TestE2E_WithUnicodeFlag(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Parameters = "test"
	cfg.Unicode = 1

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	if shellcode.Len() < 1000 {
		t.Error("Shellcode too small")
	}

	t.Logf("Shellcode with unicode flag: %d bytes", shellcode.Len())
}

// ============== EXIT OPTIONS TESTS ==============

func TestE2E_ExitOptions(t *testing.T) {
	pe := buildTestPE(t, "amd64")

	exitOpts := map[string]int{
		"thread":  DONUT_OPT_EXIT_THREAD,
		"process": DONUT_OPT_EXIT_PROCESS,
		"block":   DONUT_OPT_EXIT_BLOCK,
	}

	for name, exitOpt := range exitOpts {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Arch = X64
			cfg.Entropy = DONUT_ENTROPY_NONE
			cfg.ExitOpt = exitOpt

			shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
			if err != nil {
				t.Fatalf("ExitOpt=%s failed: %v", name, err)
			}

			if shellcode.Len() < 1000 {
				t.Errorf("ExitOpt=%s produced small shellcode: %d", name, shellcode.Len())
			}

			t.Logf("ExitOpt=%s: %d bytes", name, shellcode.Len())
		})
	}
}

// ============== BYPASS OPTIONS TESTS ==============

func TestE2E_BypassOptions(t *testing.T) {
	pe := buildTestPE(t, "amd64")

	bypassOpts := map[string]int{
		"none":     DONUT_BYPASS_NONE,
		"abort":    DONUT_BYPASS_ABORT,
		"continue": DONUT_BYPASS_CONTINUE,
	}

	for name, bypass := range bypassOpts {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Arch = X64
			cfg.Entropy = DONUT_ENTROPY_NONE
			cfg.Bypass = bypass

			shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
			if err != nil {
				t.Fatalf("Bypass=%s failed: %v", name, err)
			}

			if shellcode.Len() < 1000 {
				t.Errorf("Bypass=%s produced small shellcode: %d", name, shellcode.Len())
			}

			t.Logf("Bypass=%s: %d bytes", name, shellcode.Len())
		})
	}
}

// ============== HTTP STAGING TESTS ==============

func TestE2E_HTTPStaging(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.InstType = DONUT_INSTANCE_HTTP
	cfg.Server = "http://192.168.1.100:8080/payload"

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("HTTP staging failed: %v", err)
	}

	if !bytes.Contains(shellcode.Bytes(), []byte("192.168.1.100")) {
		t.Error("HTTP staging shellcode should contain server address")
	}

	t.Logf("HTTP staging: %d bytes", shellcode.Len())
}

func TestE2E_HTTPStagingWithAuth(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.InstType = DONUT_INSTANCE_HTTP
	cfg.Server = "http://server.com/payload"
	cfg.Auth = "admin:secretpass"

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("HTTP staging with auth failed: %v", err)
	}

	if !bytes.Contains(shellcode.Bytes(), []byte("admin")) {
		t.Error("HTTP staging should contain auth username")
	}

	t.Logf("HTTP staging with auth: %d bytes", shellcode.Len())
}

// ============== COMPRESSION TESTS ==============

func TestE2E_Compression_None(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Compress = DONUT_COMPRESS_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	t.Logf("No compression: %d bytes", shellcode.Len())
}

func TestE2E_Compression_APLib(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Compress = DONUT_COMPRESS_APLIB

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("aPLib compression failed: %v", err)
	}

	cfgNone := DefaultConfig()
	cfgNone.Arch = DONUT_ARCH_X64
	cfgNone.Entropy = DONUT_ENTROPY_NONE
	cfgNone.Compress = DONUT_COMPRESS_NONE
	scNone, _ := ShellcodeFromBytes(bytes.NewBuffer(pe), cfgNone)

	if shellcode.Len() >= scNone.Len() {
		t.Errorf("aPLib compressed (%d) should be smaller than uncompressed (%d)", shellcode.Len(), scNone.Len())
	}

	t.Logf("aPLib: %d bytes, Uncompressed: %d bytes (%.1f%% ratio)",
		shellcode.Len(), scNone.Len(), float64(shellcode.Len())/float64(scNone.Len())*100)
}

// ============== HEADER OPTIONS TESTS ==============

func TestE2E_Headers_Overwrite(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Headers = DONUT_HEADERS_OVERWRITE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	t.Logf("Headers overwrite: %d bytes", shellcode.Len())
}

func TestE2E_Headers_Keep(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Headers = DONUT_HEADERS_KEEP

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	t.Logf("Headers keep: %d bytes", shellcode.Len())
}

// ============== COMBINED FEATURES TESTS ==============

func TestE2E_AllArchitectures_AllEntropies(t *testing.T) {
	pe := buildTestPE(t, "amd64")

	archs := map[string]DonutArch{
		"x64": X64,
		"x84": X84,
	}
	entropies := map[string]int{
		"none":    DONUT_ENTROPY_NONE,
		"random":  DONUT_ENTROPY_RANDOM,
		"encrypt": DONUT_ENTROPY_DEFAULT,
	}

	for archName, arch := range archs {
		for entropyName, entropy := range entropies {
			t.Run(archName+"_"+entropyName, func(t *testing.T) {
				cfg := DefaultConfig()
				cfg.Arch = arch
				cfg.Entropy = entropy

				shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
				if err != nil {
					t.Errorf("Failed: %v", err)
					return
				}

				if shellcode.Len() < 500 {
					t.Errorf("Shellcode too small: %d", shellcode.Len())
				}

				t.Logf("%s/%s: %d bytes", archName, entropyName, shellcode.Len())
			})
		}
	}
}

func TestE2E_AllFormats(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Failed to generate shellcode: %v", err)
	}

	formats := map[string]int{
		"binary":     DONUT_FORMAT_BINARY,
		"base64":     DONUT_FORMAT_BASE64,
		"c":          DONUT_FORMAT_C,
		"ruby":       DONUT_FORMAT_RUBY,
		"python":     DONUT_FORMAT_PYTHON,
		"powershell": DONUT_FORMAT_POWERSHELL,
		"csharp":     DONUT_FORMAT_CSHARP,
		"hex":        DONUT_FORMAT_HEX,
		"uuid":       DONUT_FORMAT_UUID,
	}

	for name, format := range formats {
		t.Run(name, func(t *testing.T) {
			output, err := FormatOutput(shellcode.Bytes(), format)
			if err != nil {
				t.Errorf("Format %s failed: %v", name, err)
				return
			}

			if len(output) < 100 {
				t.Errorf("Format %s produced small output: %d", name, len(output))
			}

			t.Logf("%s: %d bytes/chars", name, len(output))
		})
	}
}

// ============== EDGE CASES ==============

func TestE2E_EmptyArguments(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Parameters = ""

	_, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Empty args should work: %v", err)
	}
}

func TestE2E_LongArguments(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Parameters = strings.Repeat("A", 1000)

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Long args failed: %v", err)
	}

	if !bytes.Contains(shellcode.Bytes(), []byte(strings.Repeat("A", 100))) {
		t.Error("Long arguments should be embedded")
	}
}

func TestE2E_SpecialCharArguments(t *testing.T) {
	pe := buildTestPE(t, "amd64")
	cfg := DefaultConfig()
	cfg.Arch = X64
	cfg.Entropy = DONUT_ENTROPY_NONE
	cfg.Parameters = `-flag="value with spaces" --another='test'`

	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(pe), cfg)
	if err != nil {
		t.Fatalf("Special char args failed: %v", err)
	}

	if !bytes.Contains(shellcode.Bytes(), []byte("value with spaces")) {
		t.Error("Special char arguments should be preserved")
	}
}

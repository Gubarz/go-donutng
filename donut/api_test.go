package donut

import (
	"testing"
)

func TestAPIOptions(t *testing.T) {
	// Test WithArch
	cfg := DefaultConfig()
	WithArch(X64)(cfg)
	if cfg.Arch != X64 {
		t.Errorf("WithArch: got %d, expected %d", cfg.Arch, X64)
	}

	// Test WithBypass
	cfg = DefaultConfig()
	WithBypass(DONUT_BYPASS_ABORT)(cfg)
	if cfg.Bypass != DONUT_BYPASS_ABORT {
		t.Errorf("WithBypass: got %d, expected %d", cfg.Bypass, DONUT_BYPASS_ABORT)
	}

	// Test WithHeaders
	cfg = DefaultConfig()
	WithHeaders(true)(cfg)
	if cfg.Headers != DONUT_HEADERS_KEEP {
		t.Errorf("WithHeaders: got %d, expected %d", cfg.Headers, DONUT_HEADERS_KEEP)
	}

	// Test WithCompression
	cfg = DefaultConfig()
	WithCompression(uint32(DONUT_COMPRESS_APLIB))(cfg)
	if cfg.Compress != uint32(DONUT_COMPRESS_APLIB) {
		t.Errorf("WithCompression: got %d, expected %d", cfg.Compress, DONUT_COMPRESS_APLIB)
	}

	// Test WithFormat
	cfg = DefaultConfig()
	WithFormat(uint32(DONUT_FORMAT_BASE64))(cfg)
	if cfg.Format != uint32(DONUT_FORMAT_BASE64) {
		t.Errorf("WithFormat: got %d, expected %d", cfg.Format, DONUT_FORMAT_BASE64)
	}

	// Test WithEntropy
	cfg = DefaultConfig()
	WithEntropy(DONUT_ENTROPY_RANDOM)(cfg)
	if cfg.Entropy != DONUT_ENTROPY_RANDOM {
		t.Errorf("WithEntropy: got %d, expected %d", cfg.Entropy, DONUT_ENTROPY_RANDOM)
	}

	// Test WithExitOption
	cfg = DefaultConfig()
	WithExitOption(DONUT_OPT_EXIT_PROCESS)(cfg)
	if cfg.ExitOpt != DONUT_OPT_EXIT_PROCESS {
		t.Errorf("WithExitOption: got %d, expected %d", cfg.ExitOpt, DONUT_OPT_EXIT_PROCESS)
	}

	// Test WithOEP
	cfg = DefaultConfig()
	WithOEP(1)(cfg)
	if cfg.OEP != 1 {
		t.Errorf("WithOEP: got %d, expected 1", cfg.OEP)
	}

	// Test WithThread
	cfg = DefaultConfig()
	WithThread(true)(cfg)
	if cfg.Thread != 1 {
		t.Errorf("WithThread: got %d, expected 1", cfg.Thread)
	}

	// Test WithUnicode
	cfg = DefaultConfig()
	WithUnicode(true)(cfg)
	if cfg.Unicode != 1 {
		t.Errorf("WithUnicode: got %d, expected 1", cfg.Unicode)
	}
}

func TestWithStringOptions(t *testing.T) {
	// Test WithClass
	cfg := DefaultConfig()
	WithClass("TestClass")(cfg)
	if cfg.Class != "TestClass" {
		t.Errorf("WithClass: got %s, expected TestClass", cfg.Class)
	}

	// Test WithMethod
	cfg = DefaultConfig()
	WithMethod("TestMethod")(cfg)
	if cfg.Method != "TestMethod" {
		t.Errorf("WithMethod: got %s, expected TestMethod", cfg.Method)
	}

	// Test WithArgs
	cfg = DefaultConfig()
	WithArgs("arg1 arg2")(cfg)
	if cfg.Parameters != "arg1 arg2" {
		t.Errorf("WithArgs: got %s, expected 'arg1 arg2'", cfg.Parameters)
	}

	// Test WithRuntime
	cfg = DefaultConfig()
	WithRuntime("v4.0.30319")(cfg)
	if cfg.Runtime != "v4.0.30319" {
		t.Errorf("WithRuntime: got %s, expected v4.0.30319", cfg.Runtime)
	}

	// Test WithDomain
	cfg = DefaultConfig()
	WithDomain("TestDomain")(cfg)
	if cfg.Domain != "TestDomain" {
		t.Errorf("WithDomain: got %s, expected TestDomain", cfg.Domain)
	}

	// Test WithServer
	cfg = DefaultConfig()
	WithServer("http://test.com")(cfg)
	if cfg.Server != "http://test.com" {
		t.Errorf("WithServer: got %s, expected http://test.com", cfg.Server)
	}

	// Test WithDecoy
	cfg = DefaultConfig()
	WithDecoy("decoy.exe")(cfg)
	if cfg.Decoy != "decoy.exe" {
		t.Errorf("WithDecoy: got %s, expected decoy.exe", cfg.Decoy)
	}
}

func TestMultipleOptions(t *testing.T) {
	cfg := DefaultConfig()

	// Apply multiple options
	opts := []Option{
		WithArch(X64),
		WithBypass(DONUT_BYPASS_CONTINUE),
		WithCompression(uint32(DONUT_COMPRESS_APLIB)),
		WithFormat(uint32(DONUT_FORMAT_BASE64)),
		WithClass("MyClass"),
		WithMethod("Main"),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// Verify all options were applied
	if cfg.Arch != X64 {
		t.Error("Arch not set correctly")
	}
	if cfg.Bypass != DONUT_BYPASS_CONTINUE {
		t.Error("Bypass not set correctly")
	}
	if cfg.Compress != uint32(DONUT_COMPRESS_APLIB) {
		t.Error("Compress not set correctly")
	}
	if cfg.Format != uint32(DONUT_FORMAT_BASE64) {
		t.Error("Format not set correctly")
	}
	if cfg.Class != "MyClass" {
		t.Error("Class not set correctly")
	}
	if cfg.Method != "Main" {
		t.Error("Method not set correctly")
	}
}

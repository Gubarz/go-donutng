package donut

// Donut key/block lengths
const (
	DONUT_KEY_LEN = 16
	DONUT_BLK_LEN = 16
)

// Target architecture
const (
	DONUT_ARCH_ANY = -1 // for vbs and js files
	DONUT_ARCH_X86 = 1  // x86
	DONUT_ARCH_X64 = 2  // AMD64
	DONUT_ARCH_X84 = 3  // x86 + AMD64
)

// Module type
const (
	DONUT_MODULE_NET_DLL = 1 // .NET DLL. Requires class and method
	DONUT_MODULE_NET_EXE = 2 // .NET EXE. Executes Main if no class and method provided
	DONUT_MODULE_DLL     = 3 // Unmanaged DLL, function is optional
	DONUT_MODULE_EXE     = 4 // Unmanaged EXE
	DONUT_MODULE_VBS     = 5 // VBScript
	DONUT_MODULE_JS      = 6 // JavaScript or JScript
)

// Output format type
const (
	DONUT_FORMAT_BINARY     = 1
	DONUT_FORMAT_BASE64     = 2
	DONUT_FORMAT_C          = 3
	DONUT_FORMAT_RUBY       = 4
	DONUT_FORMAT_PYTHON     = 5
	DONUT_FORMAT_POWERSHELL = 6
	DONUT_FORMAT_CSHARP     = 7
	DONUT_FORMAT_HEX        = 8
	DONUT_FORMAT_UUID       = 9
)

// Compression engine
const (
	DONUT_COMPRESS_NONE   = 1
	DONUT_COMPRESS_APLIB  = 2
	DONUT_COMPRESS_LZNT1  = 3 // COMPRESSION_FORMAT_LZNT1
	DONUT_COMPRESS_XPRESS = 4 // COMPRESSION_FORMAT_XPRESS
)

// Entropy level
const (
	DONUT_ENTROPY_NONE    = 1 // don't use any entropy
	DONUT_ENTROPY_RANDOM  = 2 // use random names
	DONUT_ENTROPY_DEFAULT = 3 // use random names + symmetric encryption
)

// Exit options
const (
	DONUT_OPT_EXIT_THREAD  = 1 // return to caller which calls RtlExitUserThread
	DONUT_OPT_EXIT_PROCESS = 2 // call RtlExitUserProcess to terminate host process
	DONUT_OPT_EXIT_BLOCK   = 3 // do not exit or cleanup, block indefinitely
)

// Instance type
const (
	DONUT_INSTANCE_EMBED = 1 // Module is embedded
	DONUT_INSTANCE_HTTP  = 2 // Module is downloaded from remote HTTP/HTTPS server
	DONUT_INSTANCE_DNS   = 3 // Module is downloaded from remote DNS server
)

// AMSI/WLDP/ETW bypass level
const (
	DONUT_BYPASS_NONE     = 1 // Disables bypassing AMSI/WDLP/ETW
	DONUT_BYPASS_ABORT    = 2 // If bypassing fails, the loader stops running
	DONUT_BYPASS_CONTINUE = 3 // If bypassing fails, the loader continues running
)

// Preserve PE headers options
const (
	DONUT_HEADERS_OVERWRITE = 1 // Overwrite PE headers
	DONUT_HEADERS_KEEP      = 2 // Preserve PE headers
)

// Size limits
const (
	DONUT_MAX_NAME    = 256 // maximum length of string for domain, class, method and parameter names
	DONUT_MAX_DLL     = 8   // maximum number of DLL supported by instance
	DONUT_MAX_MODNAME = 8
	DONUT_SIG_LEN     = 8 // 64-bit string to verify decryption ok
	DONUT_VER_LEN     = 32
	DONUT_DOMAIN_LEN  = 8
	DONUT_IV_LEN      = 8
	DONUT_MAX_PATH    = 260
)

// .NET runtime versions
const (
	DONUT_RUNTIME_NET2 = "v2.0.50727"
	DONUT_RUNTIME_NET4 = "v4.0.30319"
)

// DLL names used by loader
const (
	NTDLL_DLL    = "ntdll.dll"
	KERNEL32_DLL = "kernel32.dll"
	ADVAPI32_DLL = "advapi32.dll"
	CRYPT32_DLL  = "crypt32.dll"
	MSCOREE_DLL  = "mscoree.dll"
	OLE32_DLL    = "ole32.dll"
	OLEAUT32_DLL = "oleaut32.dll"
	WININET_DLL  = "wininet.dll"
	COMBASE_DLL  = "combase.dll"
	USER32_DLL   = "user32.dll"
	SHLWAPI_DLL  = "shlwapi.dll"
	SHELL32_DLL  = "shell32.dll"
)

// Error codes
const (
	DONUT_ERROR_SUCCESS           = 0
	DONUT_ERROR_FILE_NOT_FOUND    = 1
	DONUT_ERROR_FILE_EMPTY        = 2
	DONUT_ERROR_FILE_ACCESS       = 3
	DONUT_ERROR_FILE_INVALID      = 4
	DONUT_ERROR_NET_PARAMS        = 5
	DONUT_ERROR_NO_MEMORY         = 6
	DONUT_ERROR_INVALID_ARCH      = 7
	DONUT_ERROR_INVALID_URL       = 8
	DONUT_ERROR_URL_LENGTH        = 9
	DONUT_ERROR_INVALID_PARAMETER = 10
	DONUT_ERROR_RANDOM            = 11
	DONUT_ERROR_DLL_FUNCTION      = 12
	DONUT_ERROR_ARCH_MISMATCH     = 13
	DONUT_ERROR_DLL_PARAM         = 14
	DONUT_ERROR_BYPASS_INVALID    = 15
	DONUT_ERROR_NORELOC           = 16
	DONUT_ERROR_INVALID_ENCODING  = 17
	DONUT_ERROR_INVALID_ENGINE    = 18
	DONUT_ERROR_COMPRESSION       = 19
	DONUT_ERROR_INVALID_ENTROPY   = 20
	DONUT_ERROR_MIXED_ASSEMBLY    = 21
	DONUT_ERROR_HEADERS_INVALID   = 22
	DONUT_ERROR_DECOY_INVALID     = 23
)

// GUID structure matching Windows GUID
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// DonutCrypt holds encryption key and counter
type DonutCrypt struct {
	MasterKey [DONUT_KEY_LEN]byte // master key
	Counter   [DONUT_BLK_LEN]byte // counter + nonce
}

// DonutModule - everything required for a module
type DonutModule struct {
	Type     int32 // EXE/DLL/JS/VBS
	Thread   int32 // run entrypoint of unmanaged EXE as a thread
	Compress int32 // indicates engine used for compression

	Runtime [DONUT_MAX_NAME]byte // runtime version for .NET EXE/DLL
	Domain  [DONUT_MAX_NAME]byte // domain name to use for .NET EXE/DLL
	Cls     [DONUT_MAX_NAME]byte // name of class and optional namespace for .NET EXE/DLL
	Method  [DONUT_MAX_NAME]byte // name of method to invoke for .NET DLL or api for unmanaged DLL

	Args    [DONUT_MAX_NAME]byte // string arguments for both managed and unmanaged DLL/EXE
	Unicode int32                // convert param to unicode for unmanaged DLL function

	Sig [DONUT_SIG_LEN]byte // string to verify decryption
	Mac uint64              // hash of sig, to verify decryption was ok

	Zlen uint32 // compressed size of EXE/DLL/JS/VBS file
	Len  uint32 // real size of EXE/DLL/JS/VBS file
	Data []byte // data of EXE/DLL/JS/VBS file
}

// DonutInstance - everything required for an instance
type DonutInstance struct {
	Len uint32     // total size of instance
	Key DonutCrypt // decrypts instance if encryption enabled

	IV uint64 // the 64-bit initial value for maru hash

	Hash [58]uint64 // holds up to 58 api hashes (reduced from 64 for syscall support)

	SyscallList uint64 // pointer to syscall table for syswhispers2 (runtime only)

	ExitOpt int32  // 1=thread, 2=process, 3=block
	Entropy int32  // indicates entropy level
	OEP     uint32 // original entrypoint

	// everything from here is encrypted
	ApiCnt   int32                // the 64-bit hashes of API required
	DllNames [DONUT_MAX_NAME]byte // list of DLL strings to load, separated by semi-colon

	Dataname   [8]byte  // ".data"
	Kernelbase [12]byte // "kernelbase"
	Amsi       [8]byte  // "amsi"
	Clr        [4]byte  // "clr"
	Wldp       [8]byte  // "wldp"
	Ntdll      [8]byte  // "ntdll"

	CmdSyms [DONUT_MAX_NAME]byte // symbols related to command line
	ExitApi [DONUT_MAX_NAME]byte // exit-related API

	Bypass  int32 // indicates behaviour of bypassing AMSI/WLDP/ETW
	Headers int32 // indicates whether to overwrite PE headers

	WldpQuery      [32]byte // WldpQueryDynamicCodeTrust
	WldpIsApproved [32]byte // WldpIsClassInApprovedList
	AmsiInit       [16]byte // AmsiInitialize
	AmsiScanBuf    [16]byte // AmsiScanBuffer
	AmsiScanStr    [16]byte // AmsiScanString
	EtwEventWrite  [16]byte // EtwEventWrite
	EtwEventUnreg  [20]byte // EtwEventUnregister
	EtwRet64       [1]byte  // "ret" instruction for Etw
	EtwRet32       [4]byte  // "ret 14h" instruction for Etw

	Wscript    [8]byte  // WScript
	WscriptExe [12]byte // wscript.exe

	Decoy [DONUT_MAX_PATH * 2]byte // path of decoy module

	// GUIDs
	XIID_IUnknown  GUID
	XIID_IDispatch GUID

	// GUID required to load .NET assemblies
	XCLSID_CLRMetaHost    GUID
	XIID_ICLRMetaHost     GUID
	XIID_ICLRRuntimeInfo  GUID
	XCLSID_CorRuntimeHost GUID
	XIID_ICorRuntimeHost  GUID
	XIID_AppDomain        GUID

	// GUID required to run VBS and JS files
	XCLSID_ScriptLanguage        GUID
	XIID_IHost                   GUID
	XIID_IActiveScript           GUID
	XIID_IActiveScriptSite       GUID
	XIID_IActiveScriptSiteWindow GUID
	XIID_IActiveScriptParse32    GUID
	XIID_IActiveScriptParse64    GUID

	Type     int32                // DONUT_INSTANCE_EMBED, DONUT_INSTANCE_HTTP
	Server   [DONUT_MAX_NAME]byte // staging server hosting donut module
	Username [DONUT_MAX_NAME]byte // username for web server
	Password [DONUT_MAX_NAME]byte // password for web server
	HttpReq  [8]byte              // just a buffer for "GET"

	Sig [DONUT_MAX_NAME]byte // string to hash
	Mac uint64               // to verify decryption ok

	ModKey DonutCrypt // used to decrypt module
	ModLen uint64     // total size of module

	Module *DonutModule // points to module (embedded or downloaded)
}

// DonutConfig holds all configuration for shellcode generation
type DonutConfig struct {
	Len  uint32 // original length of input file
	Zlen uint32 // compressed length

	// General/misc options for loader
	Arch     DonutArch // target architecture (Sliver-compatible)
	Bypass   int       // bypass option for AMSI/WDLP
	Headers  int       // preserve PE headers option
	Compress uint32    // engine to use when compressing file via RtlCompressBuffer (Sliver-compatible)
	Entropy  int       // entropy/encryption level
	Format   uint32    // output format for loader (Sliver-compatible)
	ExitOpt  int       // return to caller, invoke RtlExitUserProcess, or block
	Thread   uint32    // run entrypoint of unmanaged EXE as a thread (Sliver-compatible)
	OEP      uint32    // original entrypoint of target host file

	// Files in/out
	Input  string // name of input file to read and load in-memory
	Output string // name of output file to save loader

	// .NET stuff
	Runtime string // runtime version to use for CLR
	Domain  string // name of domain to create for .NET DLL/EXE
	Class   string // name of class with optional namespace for .NET DLL
	Method  string // name of method or DLL function to invoke

	// Command line for DLL/EXE
	Parameters string // command line to use for unmanaged DLL/EXE and .NET DLL/EXE (Sliver-compatible, was Args)
	Unicode    uint32 // param is passed to DLL function without converting to unicode (Sliver-compatible)

	// Module overloading stuff
	Decoy string // path of decoy module

	// HTTP/DNS staging information
	Server  string // staging server hosting donut module
	Auth    string // username and password for web server (user:pass)
	ModName string // name of module written to disk for http stager

	// DONUT_MODULE
	Type   ModuleType   // VBS/JS/DLL/EXE (Sliver-compatible, was ModType)
	ModLen int          // size of DONUT_MODULE
	Mod    *DonutModule // points to DONUT_MODULE

	// DONUT_INSTANCE
	InstType InstanceType   // DONUT_INSTANCE_EMBED or DONUT_INSTANCE_HTTP (Sliver-compatible)
	InstLen  int            // size of DONUT_INSTANCE
	Inst     *DonutInstance // points to DONUT_INSTANCE

	// Shellcode generated from configuration
	PicLen int    // size of loader/shellcode
	Pic    []byte // points to loader/shellcode
}

// DefaultConfig returns a DonutConfig with sensible defaults
func DefaultConfig() *DonutConfig {
	return &DonutConfig{
		Arch:     X84,
		Bypass:   DONUT_BYPASS_CONTINUE,
		Headers:  DONUT_HEADERS_OVERWRITE,
		Compress: uint32(DONUT_COMPRESS_NONE),
		Entropy:  DONUT_ENTROPY_DEFAULT,
		Format:   uint32(DONUT_FORMAT_BINARY),
		ExitOpt:  DONUT_OPT_EXIT_THREAD,
		InstType: DONUT_INSTANCE_PIC,
		Thread:   1,
	}
}

// FileInfo holds information about input file
type FileInfo struct {
	Len   uint32
	Zlen  uint32
	Data  []byte
	Zdata []byte
	Type  int
	Arch  int
	Ver   string
}

// Error messages
var errorMessages = map[int]string{
	DONUT_ERROR_SUCCESS:           "Operation successful",
	DONUT_ERROR_FILE_NOT_FOUND:    "File not found",
	DONUT_ERROR_FILE_EMPTY:        "File is empty",
	DONUT_ERROR_FILE_ACCESS:       "Cannot access file",
	DONUT_ERROR_FILE_INVALID:      "File is invalid",
	DONUT_ERROR_NET_PARAMS:        ".NET assembly requires class and method",
	DONUT_ERROR_NO_MEMORY:         "Memory allocation failed",
	DONUT_ERROR_INVALID_ARCH:      "Invalid architecture specified",
	DONUT_ERROR_INVALID_URL:       "Invalid URL",
	DONUT_ERROR_URL_LENGTH:        "URL exceeds maximum length",
	DONUT_ERROR_INVALID_PARAMETER: "Invalid parameter",
	DONUT_ERROR_RANDOM:            "Random generation failed",
	DONUT_ERROR_DLL_FUNCTION:      "DLL function not found",
	DONUT_ERROR_ARCH_MISMATCH:     "Architecture mismatch",
	DONUT_ERROR_DLL_PARAM:         "DLL parameter error",
	DONUT_ERROR_BYPASS_INVALID:    "Invalid bypass option",
	DONUT_ERROR_NORELOC:           "File has no relocation information",
	DONUT_ERROR_INVALID_ENCODING:  "Invalid encoding",
	DONUT_ERROR_INVALID_ENGINE:    "Invalid compression engine",
	DONUT_ERROR_COMPRESSION:       "Compression failed",
	DONUT_ERROR_INVALID_ENTROPY:   "Invalid entropy level",
	DONUT_ERROR_MIXED_ASSEMBLY:    "Mixed-mode assembly not supported",
	DONUT_ERROR_HEADERS_INVALID:   "Invalid headers option",
	DONUT_ERROR_DECOY_INVALID:     "Invalid decoy module",
}

// DonutError returns a human-readable error message
func DonutError(code int) string {
	if msg, ok := errorMessages[code]; ok {
		return msg
	}
	return "Unknown error"
}

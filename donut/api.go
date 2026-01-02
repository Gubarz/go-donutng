package donut

import (
	"bytes"
	"io"
	"net/http"
	"os"
)

// API functions matching the official donut C API

// Create generates shellcode from the given configuration
// This is the main entry point for the library
func Create(config *DonutConfig) ([]byte, error) {
	err := DonutCreate(config)
	if err != nil {
		return nil, err
	}
	return config.Pic, nil
}

// ============================================================================
// Binject/go-donut Compatibility Layer
// These functions provide API compatibility with the original Binject/go-donut
// ============================================================================

// ShellcodeFromURL downloads a PE from URL and generates shellcode
// Binject-compatible API
func ShellcodeFromURL(fileURL string, config *DonutConfig) (*bytes.Buffer, error) {
	resp, err := http.Get(fileURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return ShellcodeFromBytes(bytes.NewBuffer(data), config)
}

// DownloadFile downloads a file from URL to a bytes.Buffer
// Binject-compatible utility function
func DownloadFile(url string) (*bytes.Buffer, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(data), nil
}

// ConvertArch converts DonutArch to internal arch constants
func ConvertArch(arch DonutArch) int {
	return arch.ToInternal()
}

// CreateFromFile generates shellcode from a file path
func CreateFromFile(path string, opts ...Option) ([]byte, error) {
	config := DefaultConfig()
	config.Input = path

	for _, opt := range opts {
		opt(config)
	}

	return Create(config)
}

// CreateFromBytes generates shellcode from raw bytes
func CreateFromBytes(data []byte, opts ...Option) ([]byte, error) {
	config := DefaultConfig()

	for _, opt := range opts {
		opt(config)
	}

	buf, err := ShellcodeFromBytes(bytes.NewBuffer(data), config)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CreateFromReader generates shellcode from an io.Reader
func CreateFromReader(r io.Reader, opts ...Option) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return CreateFromBytes(data, opts...)
}

// SaveToFile saves shellcode to a file with the specified format
func SaveToFile(shellcode []byte, path string, format int) error {
	output, err := FormatOutput(shellcode, format)
	if err != nil {
		return err
	}
	return os.WriteFile(path, output, 0644)
}

// Option is a functional option for configuring shellcode generation
type Option func(*DonutConfig)

// WithArch sets the target architecture
func WithArch(arch DonutArch) Option {
	return func(c *DonutConfig) {
		c.Arch = arch
	}
}

// WithBypass sets the AMSI/WLDP/ETW bypass option
func WithBypass(bypass int) Option {
	return func(c *DonutConfig) {
		c.Bypass = bypass
	}
}

// WithCompression sets the compression engine
func WithCompression(compress uint32) Option {
	return func(c *DonutConfig) {
		c.Compress = compress
	}
}

// WithEntropy sets the entropy level
func WithEntropy(entropy int) Option {
	return func(c *DonutConfig) {
		c.Entropy = entropy
	}
}

// WithFormat sets the output format
func WithFormat(format uint32) Option {
	return func(c *DonutConfig) {
		c.Format = format
	}
}

// WithExitOption sets the exit behavior
func WithExitOption(exit int) Option {
	return func(c *DonutConfig) {
		c.ExitOpt = exit
	}
}

// WithThread enables/disables thread execution
func WithThread(thread bool) Option {
	return func(c *DonutConfig) {
		if thread {
			c.Thread = 1
		} else {
			c.Thread = 0
		}
	}
}

// WithOEP sets the original entry point offset
func WithOEP(oep uint32) Option {
	return func(c *DonutConfig) {
		c.OEP = oep
	}
}

// WithClass sets the .NET class name
func WithClass(class string) Option {
	return func(c *DonutConfig) {
		c.Class = class
	}
}

// WithMethod sets the method/function name
func WithMethod(method string) Option {
	return func(c *DonutConfig) {
		c.Method = method
	}
}

// WithParameters sets the arguments/parameters (Sliver-compatible name)
func WithParameters(params string) Option {
	return func(c *DonutConfig) {
		c.Parameters = params
	}
}

// WithArgs sets the arguments/parameters (alias for WithParameters)
func WithArgs(args string) Option {
	return func(c *DonutConfig) {
		c.Parameters = args
	}
}

// WithRuntime sets the .NET CLR runtime version
func WithRuntime(runtime string) Option {
	return func(c *DonutConfig) {
		c.Runtime = runtime
	}
}

// WithDomain sets the .NET AppDomain name
func WithDomain(domain string) Option {
	return func(c *DonutConfig) {
		c.Domain = domain
	}
}

// WithServer sets the HTTP staging server URL
func WithServer(server string) Option {
	return func(c *DonutConfig) {
		c.Server = server
		c.InstType = DONUT_INSTANCE_URL
	}
}

// WithAuth sets the HTTP authentication credentials
func WithAuth(user, pass string) Option {
	return func(c *DonutConfig) {
		c.Auth = user + ":" + pass
	}
}

// WithHeaders sets whether to preserve PE headers
func WithHeaders(keep bool) Option {
	return func(c *DonutConfig) {
		if keep {
			c.Headers = DONUT_HEADERS_KEEP
		} else {
			c.Headers = DONUT_HEADERS_OVERWRITE
		}
	}
}

// WithDecoy sets the decoy module path
func WithDecoy(path string) Option {
	return func(c *DonutConfig) {
		c.Decoy = path
	}
}

// WithUnicode enables unicode parameter passing
func WithUnicode(unicode bool) Option {
	return func(c *DonutConfig) {
		if unicode {
			c.Unicode = 1
		} else {
			c.Unicode = 0
		}
	}
}

// ArchX86 sets target architecture to x86
func ArchX86() Option {
	return WithArch(X32)
}

// ArchX64 sets target architecture to x64
func ArchX64() Option {
	return WithArch(X64)
}

// NoBypass disables AMSI/WLDP/ETW bypass
func NoBypass() Option {
	return WithBypass(DONUT_BYPASS_NONE)
}

// NoEncryption disables encryption
func NoEncryption() Option {
	return WithEntropy(DONUT_ENTROPY_NONE)
}

// ExitThread sets exit to thread mode
func ExitThread() Option {
	return WithExitOption(DONUT_OPT_EXIT_THREAD)
}

// ExitProcess sets exit to process mode
func ExitProcess() Option {
	return WithExitOption(DONUT_OPT_EXIT_PROCESS)
}

// ExitBlock sets exit to block mode
func ExitBlock() Option {
	return WithExitOption(DONUT_OPT_EXIT_BLOCK)
}

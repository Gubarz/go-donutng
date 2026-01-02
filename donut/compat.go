package donut

// Compatibility layer for Binject/go-donut and Sliver API
// These types, constants, and field accessors maintain backward compatibility

// DonutArch - CPU architecture type (used by DonutConfig.Arch for Sliver compatibility)
// Values match Binject/go-donut: X32=0, X64=1, X84=2
type DonutArch int

const (
	// X32 - 32bit
	X32 DonutArch = iota
	// X64 - 64 bit
	X64
	// X84 - 32+64 bit (dual-mode)
	X84
)

// ToInternal converts DonutArch to internal DONUT_ARCH_* representation
func (a DonutArch) ToInternal() int {
	switch a {
	case X32:
		return DONUT_ARCH_X86
	case X64:
		return DONUT_ARCH_X64
	case X84:
		return DONUT_ARCH_X84
	default:
		return DONUT_ARCH_X84
	}
}

// DonutArchFromInt converts an internal DONUT_ARCH_* constant to DonutArch
func DonutArchFromInt(arch int) DonutArch {
	switch arch {
	case DONUT_ARCH_X86:
		return X32
	case DONUT_ARCH_X64:
		return X64
	case DONUT_ARCH_X84:
		return X84
	case DONUT_ARCH_ANY:
		return X84
	default:
		return X84
	}
}

// ModuleType - Module type (used by DonutConfig.Type for Sliver compatibility)
type ModuleType int

// Module type constants matching Sliver's expected values
const (
	DONUT_MODULE_TYPE_NET_DLL ModuleType = DONUT_MODULE_NET_DLL
	DONUT_MODULE_TYPE_NET_EXE ModuleType = DONUT_MODULE_NET_EXE
	DONUT_MODULE_TYPE_DLL     ModuleType = DONUT_MODULE_DLL
	DONUT_MODULE_TYPE_EXE     ModuleType = DONUT_MODULE_EXE
	DONUT_MODULE_TYPE_VBS     ModuleType = DONUT_MODULE_VBS
	DONUT_MODULE_TYPE_JS      ModuleType = DONUT_MODULE_JS
)

// InstanceType - Instance type (used by DonutConfig.InstType for Sliver compatibility)
type InstanceType int

const (
	// DONUT_INSTANCE_PIC - Self-contained/embedded (Sliver-compatible name)
	DONUT_INSTANCE_PIC InstanceType = DONUT_INSTANCE_EMBED
	// DONUT_INSTANCE_URL - Download from remote server (Sliver-compatible name)
	DONUT_INSTANCE_URL InstanceType = DONUT_INSTANCE_HTTP
)

// DONUT_MODULE_XSL - XSL with JavaScript/JScript or VBscript embedded
const DONUT_MODULE_XSL = 7

// ============================================================================
// Binject/go-donut Exported Function Aliases
// These provide exact function name compatibility with Binject/go-donut
// ============================================================================

// GenerateRandomBytes generates n random bytes (Binject-compatible name)
func GenerateRandomBytes(count int) ([]byte, error) {
	return RandomBytes(count)
}

// RandomString generates a random string of given length (Binject-compatible name)
func RandomString(length int) string {
	return randomString(length)
}

// Encrypt encrypts/decrypts data using Chaskey CTR mode (Binject-compatible name)
func Encrypt(mk []byte, ctr []byte, data []byte) []byte {
	return EncryptCTR(mk, ctr, data)
}

// Chaskey encrypts a single block using Chaskey cipher (Binject-compatible name)
func Chaskey(masterKey []byte, data []byte) []byte {
	c := newChaskeyState(masterKey)
	return c.encrypt(data)
}

// Speck performs Speck 64/128 encryption (Binject-compatible name)
func Speck(mk []byte, p uint64) uint64 {
	return speck64(mk, p)
}

// BytesToUint32s converts byte slice to uint32 slice (Binject-compatible)
func BytesToUint32s(inbytes []byte) []uint32 {
	result := make([]uint32, len(inbytes)/4)
	for i := 0; i < len(result); i++ {
		result[i] = uint32(inbytes[i*4]) |
			uint32(inbytes[i*4+1])<<8 |
			uint32(inbytes[i*4+2])<<16 |
			uint32(inbytes[i*4+3])<<24
	}
	return result
}

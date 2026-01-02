package donut

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// FormatOutput converts shellcode to the specified output format
func FormatOutput(shellcode []byte, format int) ([]byte, error) {
	switch format {
	case DONUT_FORMAT_BINARY:
		return shellcode, nil
	case DONUT_FORMAT_BASE64:
		return formatBase64(shellcode), nil
	case DONUT_FORMAT_C:
		return formatC(shellcode), nil
	case DONUT_FORMAT_RUBY:
		return formatRuby(shellcode), nil
	case DONUT_FORMAT_PYTHON:
		return formatPython(shellcode), nil
	case DONUT_FORMAT_POWERSHELL:
		return formatPowerShell(shellcode), nil
	case DONUT_FORMAT_CSHARP:
		return formatCSharp(shellcode), nil
	case DONUT_FORMAT_HEX:
		return formatHex(shellcode), nil
	case DONUT_FORMAT_UUID:
		return formatUUID(shellcode), nil
	default:
		return shellcode, nil
	}
}

func formatBase64(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}

func formatC(data []byte) []byte {
	var sb strings.Builder
	sb.WriteString("unsigned char payload[] = {\n")

	for i, b := range data {
		if i%12 == 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(fmt.Sprintf("0x%02x", b))
		if i < len(data)-1 {
			sb.WriteString(", ")
		}
		if (i+1)%12 == 0 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n};\n")
	sb.WriteString(fmt.Sprintf("// payload size: %d bytes\n", len(data)))
	return []byte(sb.String())
}

func formatRuby(data []byte) []byte {
	var sb strings.Builder
	sb.WriteString("payload = \\\n\"")

	for i, b := range data {
		sb.WriteString(fmt.Sprintf("\\x%02x", b))
		if (i+1)%15 == 0 && i < len(data)-1 {
			sb.WriteString("\" +\n\"")
		}
	}

	sb.WriteString("\"\n")
	sb.WriteString(fmt.Sprintf("# payload size: %d bytes\n", len(data)))
	return []byte(sb.String())
}

func formatPython(data []byte) []byte {
	var sb strings.Builder
	sb.WriteString("payload = b\"")

	for i, b := range data {
		sb.WriteString(fmt.Sprintf("\\x%02x", b))
		if (i+1)%15 == 0 && i < len(data)-1 {
			sb.WriteString("\"\npayload += b\"")
		}
	}

	sb.WriteString("\"\n")
	sb.WriteString(fmt.Sprintf("# payload size: %d bytes\n", len(data)))
	return []byte(sb.String())
}

func formatPowerShell(data []byte) []byte {
	var sb strings.Builder
	sb.WriteString("[Byte[]] $payload = @(\n")

	for i, b := range data {
		if i%12 == 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(fmt.Sprintf("0x%02X", b))
		if i < len(data)-1 {
			sb.WriteString(",")
		}
		if (i+1)%12 == 0 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n)\n")
	sb.WriteString(fmt.Sprintf("# payload size: %d bytes\n", len(data)))
	return []byte(sb.String())
}

func formatCSharp(data []byte) []byte {
	var sb strings.Builder
	sb.WriteString("byte[] payload = new byte[] {\n")

	for i, b := range data {
		if i%12 == 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(fmt.Sprintf("0x%02X", b))
		if i < len(data)-1 {
			sb.WriteString(", ")
		}
		if (i+1)%12 == 0 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n};\n")
	sb.WriteString(fmt.Sprintf("// payload size: %d bytes\n", len(data)))
	return []byte(sb.String())
}

func formatHex(data []byte) []byte {
	return []byte(hex.EncodeToString(data))
}

func formatUUID(data []byte) []byte {
	// Pad to multiple of 16 bytes
	padded := PadBytes(data, 16)

	var sb strings.Builder
	sb.WriteString("const char* uuids[] = {\n")

	for i := 0; i < len(padded); i += 16 {
		chunk := padded[i : i+16]
		uuid := fmt.Sprintf("  \"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\"",
			uint32(chunk[0])|uint32(chunk[1])<<8|uint32(chunk[2])<<16|uint32(chunk[3])<<24,
			uint16(chunk[4])|uint16(chunk[5])<<8,
			uint16(chunk[6])|uint16(chunk[7])<<8,
			chunk[8], chunk[9],
			chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15])
		sb.WriteString(uuid)
		if i+16 < len(padded) {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("};\n")
	sb.WriteString(fmt.Sprintf("// payload size: %d bytes (%d UUIDs)\n", len(data), len(padded)/16))
	return []byte(sb.String())
}

// GetFormatExtension returns the appropriate file extension for the format
func GetFormatExtension(format int) string {
	switch format {
	case DONUT_FORMAT_BINARY:
		return ".bin"
	case DONUT_FORMAT_BASE64:
		return ".b64"
	case DONUT_FORMAT_C:
		return ".c"
	case DONUT_FORMAT_RUBY:
		return ".rb"
	case DONUT_FORMAT_PYTHON:
		return ".py"
	case DONUT_FORMAT_POWERSHELL:
		return ".ps1"
	case DONUT_FORMAT_CSHARP:
		return ".cs"
	case DONUT_FORMAT_HEX:
		return ".hex"
	case DONUT_FORMAT_UUID:
		return ".uuid"
	default:
		return ".bin"
	}
}

package donut

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// PE constants
const (
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
	IMAGE_COR20_HEADER_SIZE              = 72
)

// CLR header structure
type ImageCor20Header struct {
	Cb                  uint32
	MajorRuntimeVersion uint16
	MinorRuntimeVersion uint16
	MetaDataRVA         uint32
	MetaDataSize        uint32
	Flags               uint32
	EntryPointToken     uint32
	ResourcesRVA        uint32
	ResourcesSize       uint32
	StrongNameSigRVA    uint32
	StrongNameSigSize   uint32
	CodeManagerTableRVA uint32
	CodeManagerTableSz  uint32
	VTableFixupsRVA     uint32
	VTableFixupsSize    uint32
	ExportAddrTableRVA  uint32
	ExportAddrTableSize uint32
	ManagedNativeHdrRVA uint32
	ManagedNativeHdrSz  uint32
}

// .NET metadata storage signature
type MDStorageSignature struct {
	Signature     uint32
	MajorVersion  uint16
	MinorVersion  uint16
	ExtraData     uint32
	VersionLength uint32
}

// PEInfo contains parsed PE information
type PEInfo struct {
	Data        []byte
	Arch        int
	Type        int
	IsDLL       bool
	IsDotNet    bool
	IsManaged   bool
	IsMixed     bool
	CLRVersion  string
	EntryPoint  uint32
	ImageBase   uint64
	Sections    []pe.SectionHeader
	Relocations bool
}

// ParsePE parses a PE file and returns detailed information
func ParsePE(data []byte) (*PEInfo, error) {
	info := &PEInfo{
		Data: data,
	}

	peFile, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	// Determine architecture
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Arch = DONUT_ARCH_X64
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Arch = DONUT_ARCH_X86
	default:
		return nil, errors.New("unsupported PE architecture")
	}

	// Check if DLL
	info.IsDLL = peFile.Characteristics&pe.IMAGE_FILE_DLL != 0

	// Check for relocations
	info.Relocations = peFile.Characteristics&pe.IMAGE_FILE_RELOCS_STRIPPED == 0

	// Get optional header info
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		info.EntryPoint = oh.AddressOfEntryPoint
		info.ImageBase = oh.ImageBase
		// Check for .NET CLR directory
		if len(oh.DataDirectory) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR {
			clrDir := oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
			if clrDir.VirtualAddress != 0 && clrDir.Size != 0 {
				info.IsDotNet = true
				info.IsManaged = true
				err = parseCLRHeader(peFile, data, clrDir.VirtualAddress, info)
				if err != nil {
					return nil, err
				}
			}
		}
	case *pe.OptionalHeader32:
		info.EntryPoint = oh.AddressOfEntryPoint
		info.ImageBase = uint64(oh.ImageBase)
		// Check for .NET CLR directory
		if len(oh.DataDirectory) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR {
			clrDir := oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
			if clrDir.VirtualAddress != 0 && clrDir.Size != 0 {
				info.IsDotNet = true
				info.IsManaged = true
				err = parseCLRHeader(peFile, data, clrDir.VirtualAddress, info)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// Copy section headers
	for _, s := range peFile.Sections {
		info.Sections = append(info.Sections, s.SectionHeader)
	}

	// Determine module type
	if info.IsDotNet {
		if info.IsDLL {
			info.Type = DONUT_MODULE_NET_DLL
		} else {
			info.Type = DONUT_MODULE_NET_EXE
		}
	} else {
		if info.IsDLL {
			info.Type = DONUT_MODULE_DLL
		} else {
			info.Type = DONUT_MODULE_EXE
		}
	}

	return info, nil
}

// parseCLRHeader parses the CLR header to get .NET version
func parseCLRHeader(peFile *pe.File, data []byte, rva uint32, info *PEInfo) error {
	// Convert RVA to file offset
	offset := rvaToOffset(peFile, rva)
	if offset < 0 || offset+IMAGE_COR20_HEADER_SIZE > len(data) {
		return errors.New("invalid CLR header offset")
	}

	// Read CLR header
	r := bytes.NewReader(data[offset:])
	var clrHdr ImageCor20Header
	if err := binary.Read(r, binary.LittleEndian, &clrHdr); err != nil {
		return err
	}

	// Check if mixed-mode assembly (has native entry point)
	if clrHdr.Flags&0x10 != 0 { // COMIMAGE_FLAGS_NATIVE_ENTRYPOINT
		info.IsMixed = true
	}

	// Get metadata to find CLR version
	if clrHdr.MetaDataRVA != 0 {
		metaOffset := rvaToOffset(peFile, clrHdr.MetaDataRVA)
		if metaOffset >= 0 && metaOffset+16 < len(data) {
			// Read metadata signature
			mr := bytes.NewReader(data[metaOffset:])
			var mdSig MDStorageSignature
			if err := binary.Read(mr, binary.LittleEndian, &mdSig); err == nil {
				// Check for valid signature (0x424A5342 = "BSJB")
				if mdSig.Signature == 0x424A5342 {
					// Read version string
					if mdSig.VersionLength > 0 && mdSig.VersionLength < 256 {
						verBytes := make([]byte, mdSig.VersionLength)
						if _, err := mr.Read(verBytes); err == nil {
							info.CLRVersion = strings.TrimRight(string(verBytes), "\x00")
						}
					}
				}
			}
		}
	}

	// Default version if not found
	if info.CLRVersion == "" {
		info.CLRVersion = DONUT_RUNTIME_NET4
	}

	return nil
}

// rvaToOffset converts RVA to file offset
func rvaToOffset(peFile *pe.File, rva uint32) int {
	for _, s := range peFile.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return int(rva - s.VirtualAddress + s.Offset)
		}
	}
	return -1
}

// DetectFileType detects the type of input file
func DetectFileType(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, errors.New("file too small")
	}

	// Check for PE signature
	if data[0] == 'M' && data[1] == 'Z' {
		info, err := ParsePE(data)
		if err != nil {
			return 0, err
		}
		return info.Type, nil
	}

	// Check for script types
	content := string(data[:min(len(data), 1024)])
	contentLower := strings.ToLower(content)

	// VBScript indicators
	if strings.Contains(contentLower, "sub ") ||
		strings.Contains(contentLower, "function ") ||
		strings.Contains(contentLower, "dim ") ||
		strings.Contains(contentLower, "wscript") {
		return DONUT_MODULE_VBS, nil
	}

	// JScript indicators
	if strings.Contains(content, "function") ||
		strings.Contains(content, "var ") ||
		strings.Contains(content, "new ActiveXObject") {
		return DONUT_MODULE_JS, nil
	}

	return 0, errors.New("unknown file type")
}

// GetLoaderForArch returns the appropriate loader for the given architecture and module type
// For x84 (dual-mode), returns nil since Sandwich handles both loaders internally
func GetLoaderForArch(arch, modType int) ([]byte, error) {
	// x84 dual-mode is handled specially by Sandwich - both loaders embedded
	if arch == DONUT_ARCH_X84 {
		return nil, nil
	}

	switch modType {
	case DONUT_MODULE_EXE, DONUT_MODULE_NET_EXE:
		if arch == DONUT_ARCH_X64 {
			return LOADER_EXE_X64, nil
		}
		return LOADER_EXE_X86, nil
	case DONUT_MODULE_DLL, DONUT_MODULE_NET_DLL:
		if arch == DONUT_ARCH_X64 {
			return LOADER_EXE_X64, nil
		}
		return LOADER_EXE_X86, nil
	case DONUT_MODULE_VBS, DONUT_MODULE_JS:
		if arch == DONUT_ARCH_X64 {
			return LOADER_EXE_X64, nil
		}
		return LOADER_EXE_X86, nil
	}
	return nil, errors.New("unsupported module type")
}

// HasExportedFunction checks if a DLL exports a specific function
func HasExportedFunction(data []byte, funcName string) bool {
	peFile, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer peFile.Close()

	// Get export directory
	var exportDirRVA uint32
	var exportDirSize uint32

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	}

	if exportDirRVA == 0 || exportDirSize == 0 {
		return false
	}

	// Find section containing exports
	var exportSection *pe.Section
	for _, s := range peFile.Sections {
		if exportDirRVA >= s.VirtualAddress && exportDirRVA < s.VirtualAddress+s.VirtualSize {
			exportSection = s
			break
		}
	}

	if exportSection == nil {
		return false
	}

	// Read export directory
	sectionData, err := exportSection.Data()
	if err != nil {
		return false
	}

	exportOffset := exportDirRVA - exportSection.VirtualAddress
	if int(exportOffset)+40 > len(sectionData) {
		return false
	}

	// Parse export directory
	numberOfNames := binary.LittleEndian.Uint32(sectionData[exportOffset+24:])
	namePointerRVA := binary.LittleEndian.Uint32(sectionData[exportOffset+32:])

	namePointerOffset := namePointerRVA - exportSection.VirtualAddress

	// Check each exported name
	for i := uint32(0); i < numberOfNames; i++ {
		if int(namePointerOffset)+int(i)*4+4 > len(sectionData) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(sectionData[namePointerOffset+i*4:])
		nameOffset := nameRVA - exportSection.VirtualAddress

		if int(nameOffset) >= len(sectionData) {
			continue
		}

		// Read null-terminated string
		var name []byte
		for j := int(nameOffset); j < len(sectionData) && sectionData[j] != 0; j++ {
			name = append(name, sectionData[j])
		}

		if string(name) == funcName {
			return true
		}
	}

	return false
}

// ReadPEFromReader reads PE data from an io.Reader
func ReadPEFromReader(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

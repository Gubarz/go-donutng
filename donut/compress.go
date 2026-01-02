package donut

// aPLib compression implementation
// Based on the aPLib algorithm by Joergen Ibsen

// CompressAPLib compresses data using aPLib algorithm
func CompressAPLib(src []byte) []byte {
	if len(src) == 0 {
		return src
	}

	// aPLib compression implementation
	dst := make([]byte, 0, len(src)*2)

	var (
		bits     uint32 = 0
		bitcount uint32 = 0
	)

	writeBit := func(bit int) {
		if bitcount == 0 {
			dst = append(dst, 0)
			bitcount = 8
		}
		bitcount--
		if bit != 0 {
			dst[len(dst)-1] |= 1 << bitcount
		}
	}

	writeGamma := func(val uint32) {
		mask := uint32(2)
		for (val & ^(mask - 1)) != 0 {
			mask <<= 1
		}
		mask >>= 1
		for mask > 1 {
			writeBit(1)
			mask >>= 1
			if (val & mask) != 0 {
				writeBit(1)
			} else {
				writeBit(0)
			}
		}
		writeBit(0)
	}

	// Simple LZ-like compression
	pos := 0
	lastOffset := 1

	for pos < len(src) {
		bestLen := 0
		bestOffset := 0

		// Find longest match
		searchStart := pos - 65535
		if searchStart < 0 {
			searchStart = 0
		}

		for i := searchStart; i < pos; i++ {
			matchLen := 0
			for pos+matchLen < len(src) && matchLen < 65535 {
				if src[i+matchLen] != src[pos+matchLen] {
					break
				}
				matchLen++
			}
			if matchLen > bestLen {
				bestLen = matchLen
				bestOffset = pos - i
			}
		}

		if bestLen >= 3 {
			// Output match
			writeBit(1)
			if bestOffset == lastOffset {
				writeBit(1)
				writeBit(1)
				writeGamma(uint32(bestLen - 1))
			} else {
				writeBit(1)
				writeBit(0)
				writeGamma(uint32((bestOffset-1)>>8) + 2)
				dst = append(dst, byte((bestOffset-1)&0xFF))
				writeGamma(uint32(bestLen - 1))
				lastOffset = bestOffset
			}
			pos += bestLen
		} else {
			// Output literal
			writeBit(0)
			dst = append(dst, src[pos])
			pos++
		}
	}

	// Add end marker
	writeBit(1)
	writeBit(1)
	writeBit(0)

	// Flush remaining bits
	_ = bits

	return dst
}

// DecompressAPLib decompresses aPLib compressed data
func DecompressAPLib(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return src, nil
	}

	dst := make([]byte, 0, len(src)*4)

	var (
		bits     uint32 = 0
		bitcount uint32 = 0
		srcPos   int    = 0
	)

	getBit := func() int {
		if bitcount == 0 {
			if srcPos >= len(src) {
				return 0
			}
			bits = uint32(src[srcPos])
			srcPos++
			bitcount = 8
		}
		bitcount--
		bit := (bits >> bitcount) & 1
		return int(bit)
	}

	getGamma := func() uint32 {
		result := uint32(1)
		for getBit() != 0 {
			result = (result << 1) + uint32(getBit())
		}
		return result
	}

	lastOffset := 1

	for srcPos < len(src) || bitcount > 0 {
		if getBit() == 0 {
			// Literal
			if srcPos >= len(src) {
				break
			}
			dst = append(dst, src[srcPos])
			srcPos++
		} else {
			if getBit() == 0 {
				// Match with new offset
				hi := getGamma() - 2
				if srcPos >= len(src) {
					break
				}
				lo := uint32(src[srcPos])
				srcPos++
				offset := int((hi << 8) + lo + 1)
				length := int(getGamma() + 1)
				lastOffset = offset

				for i := 0; i < length; i++ {
					if len(dst)-offset < 0 {
						break
					}
					dst = append(dst, dst[len(dst)-offset])
				}
			} else {
				if getBit() == 0 {
					// End marker
					break
				}
				// Match with last offset
				length := int(getGamma() + 1)
				for i := 0; i < length; i++ {
					if len(dst)-lastOffset < 0 {
						break
					}
					dst = append(dst, dst[len(dst)-lastOffset])
				}
			}
		}
	}

	return dst, nil
}

// CompressData compresses data using the specified engine
func CompressData(data []byte, engine int) ([]byte, error) {
	switch engine {
	case DONUT_COMPRESS_NONE:
		return data, nil
	case DONUT_COMPRESS_APLIB:
		return CompressAPLib(data), nil
	case DONUT_COMPRESS_LZNT1:
		// LZNT1 is Windows-specific, use aPLib as fallback
		return CompressAPLib(data), nil
	case DONUT_COMPRESS_XPRESS:
		// Xpress is Windows-specific, use aPLib as fallback
		return CompressAPLib(data), nil
	default:
		return data, nil
	}
}

// DecompressData decompresses data
func DecompressData(data []byte, engine int, originalSize int) ([]byte, error) {
	switch engine {
	case DONUT_COMPRESS_NONE:
		return data, nil
	case DONUT_COMPRESS_APLIB:
		return DecompressAPLib(data)
	default:
		return data, nil
	}
}

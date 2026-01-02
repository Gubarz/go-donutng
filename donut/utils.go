package donut

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"unicode/utf16"
)

// RandomBytes generates n random bytes
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// PackUint32 packs a uint32 in little-endian
func PackUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// PackUint64 packs a uint64 in little-endian
func PackUint64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// ToUnicode converts a string to UTF-16LE bytes
func ToUnicode(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	buf := new(bytes.Buffer)
	for _, v := range encoded {
		binary.Write(buf, binary.LittleEndian, v)
	}
	return buf.Bytes()
}

// PadBytes pads data to specified alignment
func PadBytes(data []byte, alignment int) []byte {
	if len(data)%alignment == 0 {
		return data
	}
	padLen := alignment - (len(data) % alignment)
	return append(data, make([]byte, padLen)...)
}

// ROTR64 rotates right 64-bit
func ROTR64(v uint64, n uint) uint64 {
	return (v >> n) | (v << (64 - n))
}

// ROTR32 rotates right 32-bit
func ROTR32(v uint32, n uint) uint32 {
	return (v >> n) | (v << (32 - n))
}

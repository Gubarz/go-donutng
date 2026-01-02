package donut

import (
	"encoding/binary"
)

// Maru hash constants
const (
	MARU_BLK_LEN  = 16
	MARU_HASH_LEN = 8
	MARU_IV_LEN   = 8
	MARU_MAX_STR  = 64
	SPECK_ROUNDS  = 27
)

// Maru computes the Maru hash of input with given IV
// This matches the official donut v1.1 implementation
func Maru(input []byte, iv uint64) uint64 {
	var h uint64 = iv
	var m [MARU_BLK_LEN]byte
	var idx, length int

	for end := false; !end; {
		// end of string or max len?
		if length >= len(input) || length == MARU_MAX_STR {
			// zero remainder of M
			for i := idx; i < MARU_BLK_LEN; i++ {
				m[i] = 0
			}
			// store the end bit
			m[idx] = 0x80

			// have we space in M for api length?
			if idx >= MARU_BLK_LEN-4 {
				// no, update H with E
				h ^= speck64(m[:], h)
				// zero M
				for i := 0; i < MARU_BLK_LEN; i++ {
					m[i] = 0
				}
			}
			// store total length in bits
			binary.LittleEndian.PutUint32(m[MARU_BLK_LEN-4:], uint32(length*8))
			idx = MARU_BLK_LEN
			end = true
		} else {
			// store character from api string
			m[idx] = input[length]
			idx++
			length++
		}

		if idx == MARU_BLK_LEN {
			// update H with E
			h ^= speck64(m[:], h)
			// reset idx
			idx = 0
		}
	}
	return h
}

// speck64 is the SPECK-64/128 block cipher
func speck64(mk []byte, p uint64) uint64 {
	var k [4]uint32
	var i uint32

	// copy 128-bit master key to local buffer
	for i = 0; i < 4; i++ {
		k[i] = binary.LittleEndian.Uint32(mk[i*4:])
	}

	// x.w[0] and x.w[1] from the union
	x0 := uint32(p)
	x1 := uint32(p >> 32)

	for i = 0; i < SPECK_ROUNDS; i++ {
		// encrypt 64-bit plaintext
		x0 = (rotr32(x0, 8) + x1) ^ k[0]
		x1 = rotr32(x1, 29) ^ x0 // ROTR32(29) = ROTL32(3)

		// create next 32-bit subkey
		t := k[3]
		k[3] = (rotr32(k[1], 8) + k[0]) ^ i
		k[0] = rotr32(k[0], 29) ^ k[3]
		k[1] = k[2]
		k[2] = t
	}

	// return 64-bit ciphertext
	return uint64(x0) | (uint64(x1) << 32)
}

// rotr32 rotates right 32-bit
func rotr32(v uint32, n uint32) uint32 {
	return (v >> n) | (v << (32 - n))
}

// MaruStr computes the Maru hash of a string
func MaruStr(s string, iv uint64) uint64 {
	return Maru([]byte(s), iv)
}

// APIHash computes the API hash for the given DLL and function name
// IMPORTANT: This is hash(api) XOR hash(dll), not hash(dll+api)
func APIHash(dll, function string, iv uint64) uint64 {
	return Maru([]byte(function), iv) ^ Maru([]byte(dll), iv)
}

// DefaultIV is the default initial value for Maru hash
var DefaultIV uint64 = 0x4B455253414E4F44 // "DONASREK" in little-endian

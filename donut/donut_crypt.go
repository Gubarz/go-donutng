package donut

import (
	"crypto/aes"
	"crypto/cipher"
)

// chaskeyState is the internal Chaskey cipher state
type chaskeyState struct {
	key [4]uint32
}

// newChaskeyState creates a new Chaskey cipher with the given key
func newChaskeyState(key []byte) *chaskeyState {
	c := &chaskeyState{}
	if len(key) >= 16 {
		c.key[0] = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
		c.key[1] = uint32(key[4]) | uint32(key[5])<<8 | uint32(key[6])<<16 | uint32(key[7])<<24
		c.key[2] = uint32(key[8]) | uint32(key[9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
		c.key[3] = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24
	}
	return c
}

// encrypt encrypts a block using Chaskey
func (c *chaskeyState) encrypt(data []byte) []byte {
	if len(data) < 16 {
		return data
	}

	w0 := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	w1 := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
	w2 := uint32(data[8]) | uint32(data[9])<<8 | uint32(data[10])<<16 | uint32(data[11])<<24
	w3 := uint32(data[12]) | uint32(data[13])<<8 | uint32(data[14])<<16 | uint32(data[15])<<24

	// add 128-bit master key
	w0 ^= c.key[0]
	w1 ^= c.key[1]
	w2 ^= c.key[2]
	w3 ^= c.key[3]

	// 16 rounds of permutation - EXACT order from donut's chaskey
	for i := 0; i < 16; i++ {
		w0 += w1
		w1 = rotr32c(w1, 27) ^ w0
		w2 += w3
		w3 = rotr32c(w3, 24) ^ w2
		w2 += w1
		w0 = rotr32c(w0, 16) + w3
		w3 = rotr32c(w3, 19) ^ w0
		w1 = rotr32c(w1, 25) ^ w2
		w2 = rotr32c(w2, 16)
	}

	// add 128-bit master key
	w0 ^= c.key[0]
	w1 ^= c.key[1]
	w2 ^= c.key[2]
	w3 ^= c.key[3]

	out := make([]byte, 16)
	out[0] = byte(w0)
	out[1] = byte(w0 >> 8)
	out[2] = byte(w0 >> 16)
	out[3] = byte(w0 >> 24)
	out[4] = byte(w1)
	out[5] = byte(w1 >> 8)
	out[6] = byte(w1 >> 16)
	out[7] = byte(w1 >> 24)
	out[8] = byte(w2)
	out[9] = byte(w2 >> 8)
	out[10] = byte(w2 >> 16)
	out[11] = byte(w2 >> 24)
	out[12] = byte(w3)
	out[13] = byte(w3 >> 8)
	out[14] = byte(w3 >> 16)
	out[15] = byte(w3 >> 24)

	return out
}

// rotr32c rotates right 32-bit for Chaskey
func rotr32c(v uint32, n uint32) uint32 {
	return (v >> n) | (v << (32 - n))
}

// EncryptCTR encrypts data using Chaskey in CTR mode
func EncryptCTR(key, ctr, data []byte) []byte {
	c := newChaskeyState(key)
	out := make([]byte, len(data))
	counter := make([]byte, 16)
	copy(counter, ctr)

	for i := 0; i < len(data); i += 16 {
		keystream := c.encrypt(counter)
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		for j := i; j < end; j++ {
			out[j] = data[j] ^ keystream[j-i]
		}
		// Increment counter from the END (like donut does)
		// for(i=CIPHER_BLK_LEN;(int)i>0;i--) if(++c[i-1]) break;
		for k := 15; k >= 0; k-- {
			counter[k]++
			if counter[k] != 0 {
				break
			}
		}
	}
	return out
}

// AESEncryptCBC encrypts data using AES-CBC
func AESEncryptCBC(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := PadBytes(data, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, padded)

	return encrypted, nil
}

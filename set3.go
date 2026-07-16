package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand "math/rand/v2"
	"time"
)

func newCBCPaddingOracle(plaintext []byte) (
	encrypt func() []byte,
	isPaddingValid func([]byte) bool,
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encrypt = func() []byte {
		iv := make([]byte, aesBlockSize)
		rand.Read(iv)

		ciphertext := encryptCBC(iv, padPKCS7(plaintext, aesBlockSize), block)
		return append(iv, ciphertext...)
	}
	isPaddingValid = func(input []byte) bool {
		iv, ciphertext := input[:aesBlockSize], input[aesBlockSize:]
		decrypted := decryptCBC(iv, ciphertext, block)
		return unpadPKCS7(decrypted) != nil
	}
	return
}

func breakCBCPaddingOracle(ciphertext []byte, isPaddingValid func([]byte) bool) []byte {
	decryptBlock := func(ctPrev, ctCurr []byte) []byte {
		decryptedBlock := make([]byte, aesBlockSize)
		work := make([]byte, 2*aesBlockSize)
		copy(work, ctPrev)
		copy(work[aesBlockSize:], ctCurr)

		for i := byte(0x01); i <= aesBlockSize; i++ {
			for b := range 256 {
				work[aesBlockSize-i] = byte(b)
				if isPaddingValid(work) {
					if i == 0x01 {
						// Check for the case where the message ended with [0x02, X], and we happened to set X to 0x02 instead of 0x01.
						work[aesBlockSize-2] ^= 0x01
						if !isPaddingValid(work) {
							continue
						}
					}

					decryptedBlock[aesBlockSize-i] = ctPrev[aesBlockSize-i] ^ byte(b) ^ i
					break
				}
			}

			for j := byte(1); j <= i; j++ {
				work[aesBlockSize-j] = ctPrev[aesBlockSize-j] ^ decryptedBlock[aesBlockSize-j] ^ (i + 1)
			}
		}

		return decryptedBlock
	}

	var decrypted []byte
	for i := 0; i < len(ciphertext)-aesBlockSize; i += aesBlockSize {
		ctPrev := ciphertext[i : i+aesBlockSize]
		ctCurr := ciphertext[i+aesBlockSize : i+2*aesBlockSize]
		decryptedBlock := decryptBlock(ctPrev, ctCurr)
		decrypted = append(decrypted, decryptedBlock...)
	}
	return decrypted
}

func encryptCTR(nonce, bs []byte, block cipher.Block) []byte {
	keyStream := make([]byte, block.BlockSize())
	secret := make([]byte, block.BlockSize())
	copy(secret, nonce)

	var res []byte
	for i := 0; i < len(bs); i += block.BlockSize() {
		binary.LittleEndian.PutUint64(secret[len(nonce):], uint64(i/block.BlockSize()))
		block.Encrypt(keyStream, secret)

		blockLength := min(len(keyStream), len(bs[i:]))
		res = append(res, fixedXor(keyStream[:blockLength], bs[i:i+blockLength])...)
	}
	return res
}

var decryptCTR = encryptCTR

func breakCTRReusedNonce(ciphertexts [][]byte, freq []float64) []byte {
	uppercaseFreq := make([]float64, len(freq))
	for c := 'A'; c <= 'Z'; c++ {
		uppercaseFreq[c] = freq[c]
	}

	column := make([]byte, len(ciphertexts))
	maxLength := 0
	for _, ciphertext := range ciphertexts {
		maxLength = max(maxLength, len(ciphertext))
	}

	var keyStream []byte
	for i := range maxLength {
		columnLength := 0
		for _, ciphertext := range ciphertexts {
			if i >= len(ciphertext) {
				continue
			}
			column[columnLength] = ciphertext[i]
			columnLength++
		}

		var k byte
		if i == 0 {
			k, _, _ = detectSingleByteXOR(column[:columnLength], uppercaseFreq)
		} else {
			k, _, _ = detectSingleByteXOR(column[:columnLength], freq)
		}
		keyStream = append(keyStream, k)
	}
	return keyStream
}

const (
	mtN         = 624
	mtM         = 397
	mtMatrixA   = 0x9908b0df
	mtUpperMask = 0x80000000
	mtLowerMask = 0x7fffffff
)

var mtMag01 = [...]uint32{0x00, mtMatrixA}

// Source: https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/emt.html
type mt19937 struct {
	state [mtN]uint32
	index int
}

func newMT19937(seed uint32) *mt19937 {
	var mt mt19937
	mt.state[0] = seed
	for mt.index = 1; mt.index < mtN; mt.index++ {
		mt.state[mt.index] = 1812433253*(mt.state[mt.index-1]^(mt.state[mt.index-1]>>30)) + uint32(mt.index)
	}
	return &mt
}

func (mt *mt19937) generate() uint32 {
	if mt.index >= mtN {
		mt.twist()
	}

	y := mt.state[mt.index]
	mt.index++
	return temper(y)
}

func (mt *mt19937) twist() {
	var kk int
	var y uint32
	for kk = 0; kk < mtN-mtM; kk++ {
		y = (mt.state[kk] & mtUpperMask) | (mt.state[kk+1] & mtLowerMask)
		mt.state[kk] = mt.state[kk+mtM] ^ (y >> 1) ^ mtMag01[y&0x01]
	}
	for ; kk < mtN-1; kk++ {
		y = (mt.state[kk] & mtUpperMask) | (mt.state[kk+1] & mtLowerMask)
		mt.state[kk] = mt.state[kk+(mtM-mtN)] ^ (y >> 1) ^ mtMag01[y&0x01]
	}
	y = (mt.state[mtN-1] & mtUpperMask) | (mt.state[0] & mtLowerMask)
	mt.state[mtN-1] = mt.state[mtM-1] ^ (y >> 1) ^ mtMag01[y&0x01]
	mt.index = 0
}

func temper(y uint32) uint32 {
	y ^= (y >> 11)
	y ^= ((y << 7) & 0x9d2c5680)
	y ^= ((y << 15) & 0xefc60000)
	y ^= (y >> 18)
	return y
}

const (
	minSleep = 40
	maxSleep = 100
)

func generateFromTimeSeed() uint32 {
	sleep := minSleep + mathrand.Int64N(maxSleep-minSleep+1)
	time.Sleep(time.Duration(sleep) * time.Millisecond)

	seed := time.Now().UnixMilli()

	sleep = minSleep + mathrand.Int64N(maxSleep-minSleep+1)
	time.Sleep(time.Duration(sleep) * time.Millisecond)

	return newMT19937(uint32(seed)).generate()
}

func crackMT19937(r uint32, maxIter int) uint32 {
	seed := time.Now().UnixMilli()
	for range maxIter {
		mt := newMT19937(uint32(seed))
		if mt.generate() == r {
			return uint32(seed)
		}
		seed--
	}
	panic(fmt.Sprintf("MT19937 not cracked within %d iterations", maxIter))
}

func recoverMT19937Seed(samples [mtN]uint32) [mtN]uint32 {
	var state [mtN]uint32
	for i := range state {
		y := untemper(samples[len(samples)-i-1])
		state[len(samples)-i-1] = y
	}
	return state
}

func untemper(y uint32) uint32 {
	y = untemperRightShiftXor(y, 18)
	y = untemperLeftShiftXorAnd(y, 15, 0xefc60000)
	y = untemperLeftShiftXorAnd(y, 7, 0x9d2c5680)
	y = untemperRightShiftXor(y, 11)
	return y
}

func untemperRightShiftXor(y uint32, shift int) uint32 {
	x := y
	for range 32/shift + 1 {
		x = y ^ (x >> shift)
	}
	return x
}

func untemperLeftShiftXorAnd(y uint32, shift, mask uint32) uint32 {
	x := y
	for range 32/shift + 1 {
		x = y ^ ((x << shift) & mask)
	}
	return x
}

func encryptMT19937(key uint16, bs []byte) []byte {
	mt := newMT19937(uint32(key))
	keyStream := make([]byte, len(bs))
	for i := 0; i < len(keyStream)-3; i += 4 {
		r := mt.generate()
		keyStream[i+0] = byte(r >> 0)
		keyStream[i+1] = byte(r >> 1)
		keyStream[i+2] = byte(r >> 2)
		keyStream[i+3] = byte(r >> 3)
	}
	return fixedXor(keyStream, bs)
}

func newMT19937EncryptionOracle() func([]byte) []byte {
	var key [2]byte
	rand.Read(key[:])
	seed := binary.LittleEndian.Uint16(key[:])

	prefixLength := 10 + mathrand.IntN(40)
	prefix := make([]byte, prefixLength)
	rand.Read(prefix)

	return func(plaintext []byte) []byte {
		bs := append(prefix, plaintext...)
		return encryptMT19937(seed, bs)
	}
}

func recoverMT19937Key(plaintext, ciphertext []byte) (uint16, bool) {
	for i := 0; i < 65536; i++ {
		bs := encryptMT19937(uint16(i), ciphertext)
		if bytes.HasSuffix(bs, plaintext) {
			return uint16(i), true
		}
	}
	return 0, false
}

func generateMT19937Token() []byte {
	seed := uint32(time.Now().Unix())
	mt := newMT19937(seed)
	var token [32]byte
	for i := 0; i < len(token); i += 4 {
		r := mt.generate()
		token[i+0] = byte(r >> 0)
		token[i+1] = byte(r >> 1)
		token[i+2] = byte(r >> 2)
		token[i+3] = byte(r >> 3)
	}
	return token[:]
}

func detectMT19937Token(bs []byte) bool {
	token := make([]byte, len(bs))
	for i := uint32(0); i < 60*60*24; i++ {
		seed := uint32(time.Now().Unix()) - i
		mt := newMT19937(uint32(seed))

		for i := 0; i < len(token); i += 4 {
			r := mt.generate()
			token[i+0] = byte(r >> 0)
			token[i+1] = byte(r >> 1)
			token[i+2] = byte(r >> 2)
			token[i+3] = byte(r >> 3)
		}

		if bytes.Equal(bs, token) {
			return true
		}
	}
	return false
}

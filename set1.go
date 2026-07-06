package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/bits"
)

func hexToBase64(s string) string {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(decoded)
}

func fixedXor(bs1, bs2 []byte) []byte {
	if len(bs1) != len(bs2) {
		panic("buffer lengths differ")
	}
	xor := make([]byte, len(bs1))
	for i := range bs1 {
		xor[i] = bs1[i] ^ bs2[i]
	}
	return xor
}

func byteFrequency(bs []byte) []float64 {
	freq := make([]float64, 256)
	for _, r := range bs {
		freq[r]++
	}
	length := float64(len(bs))
	for k, v := range freq {
		freq[k] = v / length
	}
	return freq
}

func scoreEnglishText(bs []byte, freq []float64) float64 {
	score := 0.0
	for _, r := range bs {
		score += freq[r]
	}
	return score / float64(len(bs))
}

func singleByteXOR(bs []byte, key byte) []byte {
	res := make([]byte, len(bs))
	for i, b := range bs {
		res[i] = b ^ key
	}
	return res
}

func detectSingleByteXOR(bs []byte, freq []float64) (key byte, plaintext []byte, score float64) {
	for b := range 256 {
		res := singleByteXOR(bs, byte(b))
		resScore := scoreEnglishText(res, freq)
		if resScore > score {
			score = resScore
			key = byte(b)
			plaintext = res
		}
	}
	return
}

func repeatingKeyXOR(bs, key []byte) []byte {
	res := make([]byte, len(bs))
	for i, b := range bs {
		res[i] = b ^ key[i%len(key)]
	}
	return res
}

func hammingDistance(bs1, bs2 []byte) int {
	if len(bs1) != len(bs2) {
		panic("buffer lengths differ")
	}
	dist := 0
	for i := range bs1 {
		dist += bits.OnesCount8(bs1[i] ^ bs2[i])
	}
	return dist
}

func findRepeatingKeySize(bs []byte) int {
	var keySize int
	minHammingDistance := math.MaxFloat64
	for k := 2; k <= 40; k++ {
		block1, block2 := bs[:4*k], bs[4*k:8*k]
		dist := float64(hammingDistance(block1, block2)) / float64(k)
		if dist < minHammingDistance {
			minHammingDistance = dist
			keySize = k
		}
	}
	return keySize
}

func findRepeatingKey(bs []byte, keySize int, freq []float64) []byte {
	key := make([]byte, keySize)
	block := make([]byte, (len(bs)+keySize-1)/keySize)
	for col := range keySize {
		for i := range block {
			if i*keySize+col >= len(bs) {
				break
			}
			block[i] = bs[i*keySize+col]
		}
		k, _, _ := detectSingleByteXOR(block, freq)
		key[col] = k
	}
	return key
}

func encryptECB(bs []byte, block cipher.Block) []byte {
	if len(bs)%block.BlockSize() != 0 {
		panic("length of plaintext not a multiple of block size")
	}
	res := make([]byte, len(bs))
	for i := 0; i < len(bs); i += block.BlockSize() {
		block.Encrypt(res[i:], bs[i:])
	}
	return res
}

func decryptECB(bs []byte, block cipher.Block) []byte {
	if len(bs)%block.BlockSize() != 0 {
		panic("length of ciphertext not a multiple of block size")
	}
	res := make([]byte, len(bs))
	for i := 0; i < len(bs); i += block.BlockSize() {
		block.Decrypt(res[i:], bs[i:])
	}
	return res
}

func detectECB(bs []byte, blockSize int) bool {
	if len(bs)%blockSize != 0 {
		panic("length of ciphertext not a multiple of block size")
	}
	seen := make(map[string]struct{})
	for i := 0; i < len(bs); i += blockSize {
		block := string(bs[i : i+blockSize])
		if _, ok := seen[block]; ok {
			return true
		}
		seen[block] = struct{}{}
	}
	return false
}

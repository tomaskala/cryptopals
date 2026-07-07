package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	mathrand "math/rand/v2"
)

func padPKCS7(bs []byte, blockSize byte) []byte {
	padLength := int(blockSize) - len(bs)%int(blockSize)
	res := make([]byte, len(bs)+padLength)
	copy(res, bs)
	for i := range padLength {
		res[len(bs)+i] = byte(padLength)
	}
	return res
}

func unpadPKCS7(bs []byte) []byte {
	if len(bs) == 0 {
		return bs
	}
	padding := int(bs[len(bs)-1])
	if padding == 0 || padding > len(bs) {
		return nil
	}
	for i := range padding {
		if bs[len(bs)-i-1] != byte(padding) {
			return nil
		}
	}
	return bs[:len(bs)-padding]
}

func encryptCBC(bs, iv []byte, block cipher.Block) []byte {
	if len(bs)%block.BlockSize() != 0 {
		panic("length of plaintext not a multiple of block size")
	}
	if len(iv) != block.BlockSize() {
		panic("length of iv differs from the block size")
	}
	res := make([]byte, len(bs))
	prev := iv
	for i := 0; i < len(bs); i += block.BlockSize() {
		copy(res[i:i+block.BlockSize()], fixedXor(bs[i:i+block.BlockSize()], prev))
		block.Encrypt(res[i:], res[i:])
		prev = res[i : i+block.BlockSize()]
	}
	return res
}

func decryptCBC(bs, iv []byte, block cipher.Block) []byte {
	if len(bs)%block.BlockSize() != 0 {
		panic("length of ciphertext not a multiple of block size")
	}
	if len(iv) != block.BlockSize() {
		panic("length of iv differs from the block size")
	}
	res := make([]byte, len(bs))
	buf := make([]byte, block.BlockSize())
	prev := iv
	for i := 0; i < len(bs); i += block.BlockSize() {
		block.Decrypt(buf, bs[i:])
		copy(res[i:], fixedXor(buf, prev))
		prev = bs[i : i+block.BlockSize()]
	}
	return res
}

func newECBCBCOracle() func([]byte) []byte {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return func(bs []byte) []byte {
		prefix := make([]byte, 5+mathrand.IntN(6))
		rand.Read(prefix)

		suffix := make([]byte, 5+mathrand.IntN(6))
		rand.Read(suffix)

		buf := padPKCS7(append(append(prefix, bs...), suffix...), aesBlockSize)

		if mathrand.Float64() <= 0.5 {
			return encryptECB(buf, block)
		}

		iv := make([]byte, aesBlockSize)
		rand.Read(iv)
		return encryptCBC(buf, iv, block)
	}
}

func newECBSuffixOracle(suffix []byte) func([]byte) []byte {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return func(bs []byte) []byte {
		buf := padPKCS7(append(bs, suffix...), aesBlockSize)
		return encryptECB(buf, block)
	}
}

func breakECBSuffixOracle(oracle func([]byte) []byte) []byte {
	var blockSize int
	for b := 2; b <= 64; b++ {
		msg := bytes.Repeat([]byte{'A'}, 2*b)
		msg = append(msg, 'B')
		ciphertext := oracle(msg)
		if detectECB(ciphertext[:2*b], b) {
			blockSize = b
			break
		}
	}

	if blockSize == 0 {
		panic("can only break the ECB mode")
	}

	buildDictionary := func(known []byte) map[string]byte {
		dict := make(map[string]byte)
		buf := bytes.Repeat([]byte{'A'}, blockSize)
		buf = append(buf, known...)
		buf = append(buf, ' ')
		buf = buf[len(buf)-blockSize:]

		for b := range 256 {
			buf[len(buf)-1] = byte(b)
			res := string(oracle(buf)[:blockSize])
			dict[res] = byte(b)
		}

		return dict
	}

	targetLen := len(oracle(nil))
	target := make([]byte, targetLen)

	for i := range len(target) {
		dict := buildDictionary(target[:i])
		attack := bytes.Repeat([]byte{'A'}, modulo(blockSize-i-1, blockSize))
		skip := (i / blockSize) * blockSize
		res := string(oracle(attack)[skip : skip+blockSize])
		target[i] = dict[res]
	}

	return target
}

func modulo(a, b int) int {
	return (a%b + b) % b
}

func newECBPrefixSuffixOracle(suffix []byte) func([]byte) []byte {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	prefixLen := mathrand.IntN(500)
	prefix := make([]byte, prefixLen)
	rand.Read(prefix)

	return func(bs []byte) []byte {
		buf := padPKCS7(append(prefix, append(bs, suffix...)...), aesBlockSize)
		return encryptECB(buf, block)
	}
}

func breakECBPrefixSuffixOracle(oracle func([]byte) []byte) []byte {
	var prefixLen int
	found := false

	findRepetitionStart := func(bs []byte) int {
		for i := 0; i < len(bs)-2*aesBlockSize; i += aesBlockSize {
			if bytes.Equal(bs[i:i+aesBlockSize], bs[i+aesBlockSize:i+2*aesBlockSize]) {
				return i
			}
		}
		return -1
	}

	for p := range aesBlockSize {
		padding := bytes.Repeat([]byte{'P'}, p)
		repetition := bytes.Repeat([]byte{'A'}, 2*aesBlockSize)
		query := append(padding, append(repetition, 'S')...)

		ciphertext := oracle(query)
		if start := findRepetitionStart(ciphertext); start >= 0 {
			prefixLen = start - p
			found = true
			break
		}
	}

	if !found {
		panic("prefix length not found")
	}

	return breakECBSuffixOracle(func(bs []byte) []byte {
		paddingLen := aesBlockSize - prefixLen%aesBlockSize
		attack := append(bytes.Repeat([]byte{'P'}, paddingLen), bs...)
		return oracle(attack)[prefixLen+paddingLen:]
	})
}

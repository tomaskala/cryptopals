package cryptopals

import (
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
	key := make([]byte, 16)
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

		buf := padPKCS7(append(append(prefix, bs...), suffix...), 16)

		if mathrand.Float64() <= 0.5 {
			return encryptECB(buf, block)
		}

		iv := make([]byte, 16)
		rand.Read(iv)
		return encryptCBC(buf, iv, block)
	}
}

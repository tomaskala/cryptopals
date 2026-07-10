package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
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

		ciphertext := encryptCBC(padPKCS7(plaintext, aesBlockSize), iv, block)
		return append(iv, ciphertext...)
	}
	isPaddingValid = func(input []byte) bool {
		iv, ciphertext := input[:aesBlockSize], input[aesBlockSize:]
		decrypted := decryptCBC(ciphertext, iv, block)
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

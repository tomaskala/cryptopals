package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
	"strings"
)

func newRandomAccessCTROracle() (
	encrypt func([]byte) []byte,
	edit func([]byte, int, []byte) []byte,
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	nonce := make([]byte, aesBlockSize/2)
	rand.Read(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encrypt = func(plaintext []byte) []byte {
		return append(nonce, encryptCTR(nonce, plaintext, block)...)
	}
	edit = func(ciphertext []byte, offset int, newText []byte) []byte {
		nonce := ciphertext[:aesBlockSize/2]
		bs := ciphertext[aesBlockSize/2:]

		plaintext := decryptCTR(nonce, bs, block)
		copy(plaintext[offset:], newText)

		return encrypt(plaintext)
	}
	return
}

func breakRandomAccessCTR(ciphertext []byte, edit func([]byte, int, []byte) []byte) []byte {
	var plaintext []byte
	for offset := aesBlockSize / 2; offset < len(ciphertext); offset++ {
		newCiphertext := edit(ciphertext, offset-aesBlockSize/2, []byte{'A'})
		plaintext = append(plaintext, ciphertext[offset]^newCiphertext[offset]^'A')
	}
	return plaintext
}

func newCTRCookieOracle() (
	generateCookie func(string) string,
	isAdmin func(string) bool,
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	nonce := make([]byte, aesBlockSize/2)
	rand.Read(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	generateCookie = func(input string) string {
		sanitized := strings.ReplaceAll(input, ";", "")
		sanitized = strings.ReplaceAll(sanitized, "=", "")
		cookie := prefix + sanitized + suffix
		return string(encryptCTR(nonce, []byte(cookie), block))
	}
	isAdmin = func(s string) bool {
		buf := decryptCTR(nonce, []byte(s), block)
		return strings.Contains(string(buf), ";admin=true;")
	}
	return
}

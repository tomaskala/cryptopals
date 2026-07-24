package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"regexp"
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

var printableASCII = regexp.MustCompile("^[ -~]+$")

func newCBCSharedKeyIVOracle() (
	encryptMessage func([]byte) []byte,
	decryptMessage func([]byte) error,
	checkKey func([]byte) bool,
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encryptMessage = func(bs []byte) []byte {
		buf := padPKCS7(bs, aesBlockSize)
		return encryptCBC(key, buf, block)
	}
	decryptMessage = func(bs []byte) error {
		buf := unpadPKCS7(decryptCBC(key, bs, block))
		if !printableASCII.Match(buf) {
			return fmt.Errorf("invalid message: %s", buf)
		}
		return nil
	}
	checkKey = func(bs []byte) bool {
		return bytes.Equal(bs, key)
	}
	return
}

func breakCBCSharedKeyIVOracle(encrypt func([]byte) []byte, decrypt func([]byte) error) []byte {
	msg := bytes.Repeat([]byte{'A'}, 4*aesBlockSize)
	ciphertext := encrypt(msg)

	for i := range aesBlockSize {
		ciphertext[aesBlockSize+i] = 0x00
		ciphertext[2*aesBlockSize+i] = ciphertext[i]
	}

	err := decrypt(ciphertext)
	if err == nil {
		return nil
	}

	plaintext := []byte(strings.TrimPrefix(err.Error(), "invalid message: "))
	p1 := plaintext[:aesBlockSize]
	p3 := plaintext[2*aesBlockSize : 3*aesBlockSize]
	return fixedXor(p1, p3)
}

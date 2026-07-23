package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge25(t *testing.T) {
	bs := base64Decode(t, string(readFile(t, "resources/challenge07.txt")))
	key := []byte("YELLOW SUBMARINE")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := decryptECB(bs, block)

	encrypt, edit := newRandomAccessCTROracle()
	ciphertext := encrypt(plaintext)

	recovered := breakRandomAccessCTR(ciphertext, edit)
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("expected: %s, got: %s", plaintext, recovered)
	}
}

func TestChallenge26(t *testing.T) {
	generateCookie, isAdmin := newCTRCookieOracle()

	if isAdmin(generateCookie("")) {
		t.Fatalf("already admin")
	}

	query := "AadminAtrueA"
	cookie := generateCookie(query)
	attack := []byte(cookie)
	attack[32+0] ^= query[0] ^ ';'
	attack[32+6] ^= query[6] ^ '='
	attack[32+11] ^= query[11] ^ ';'

	if !isAdmin(string(attack)) {
		t.Errorf("not an admin")
	}
}

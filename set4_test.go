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

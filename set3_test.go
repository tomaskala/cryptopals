package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge17(t *testing.T) {
	plaintexts := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	for _, plaintext := range plaintexts {
		input := base64Decode(t, plaintext)
		encrypt, isPaddingValid := newCBCPaddingOracle(input)
		ciphertext := encrypt()
		decrypted := unpadPKCS7(breakCBCPaddingOracle(ciphertext, isPaddingValid))

		t.Logf("decrypted: %s", decrypted)
		if !bytes.Equal(decrypted, input) {
			t.Errorf("expected %s, got %s", input, decrypted)
		}
	}
}

func TestChallenge18(t *testing.T) {
	ciphertext := base64Decode(t, "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	nonce := make([]byte, aesBlockSize/2)
	key := []byte("YELLOW SUBMARINE")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := decryptCTR(nonce, ciphertext, block)
	t.Logf("plaintext: %s", plaintext)

	reencrypted := encryptCTR(nonce, plaintext, block)
	if !bytes.Equal(ciphertext, reencrypted) {
		t.Errorf("expected: %v, got: %v", ciphertext, reencrypted)
	}

	redecrypted := decryptCTR(nonce, reencrypted, block)
	if !bytes.Equal(plaintext, redecrypted) {
		t.Errorf("expected: %v, got: %v", plaintext, redecrypted)
	}
}

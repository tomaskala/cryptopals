package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge09(t *testing.T) {
	var padded, res []byte
	unpadded := []byte("YELLOW SUBMARINE")

	padded = []byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
	res = padPKCS7(unpadded, 16)
	if !bytes.Equal(padded, res) {
		t.Errorf("padding expected: %v, got: %v", padded, res)
	}
	res = unpadPKCS7(padded)
	if !bytes.Equal(unpadded, res) {
		t.Errorf("unpadding expected: %v, got: %v", unpadded, res)
	}

	padded = []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	res = padPKCS7(unpadded, 20)
	if !bytes.Equal(padded, res) {
		t.Errorf("padding expected: %v, got: %v", padded, res)
	}
	res = unpadPKCS7(padded)
	if !bytes.Equal(unpadded, res) {
		t.Errorf("unpadding expected: %v, got: %v", unpadded, res)
	}

	padded = []byte("YELLOW SUBMARINE\x01")
	res = padPKCS7(unpadded, 17)
	if !bytes.Equal(padded, res) {
		t.Errorf("padding expected: %v, got: %v", padded, res)
	}
	res = unpadPKCS7(padded)
	if !bytes.Equal(unpadded, res) {
		t.Errorf("unpadding expected: %v, got: %v", unpadded, res)
	}

	padded = []byte("YELLOW SUBMARINE\x02\x02")
	res = padPKCS7(unpadded, 18)
	if !bytes.Equal(padded, res) {
		t.Errorf("padding expected: %v, got: %v", padded, res)
	}
	res = unpadPKCS7(padded)
	if !bytes.Equal(unpadded, res) {
		t.Errorf("unpadding expected: %v, got: %v", unpadded, res)
	}

	if res := unpadPKCS7([]byte("YELLOW SUBMARINE\x01\x02\x03\x04")); res != nil {
		t.Errorf("unpadding expected nil, got %v", res)
	}

	if !bytes.Equal(unpadPKCS7([]byte("\x04\x04\x04\x04")), []byte{}) {
		t.Errorf("unpadding expected empty slice, got %v", res)
	}
}

func TestChallenge10(t *testing.T) {
	ciphertext := base64Decode(t, string(readFile(t, "resources/challenge10.txt")))
	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := decryptCBC(ciphertext, iv, block)
	t.Logf("plaintext: %s", plaintext)

	reencrypted := encryptCBC(plaintext, iv, block)
	if !bytes.Equal(ciphertext, reencrypted) {
		t.Errorf("expected: %v, got: %v", ciphertext, reencrypted)
	}

	redecrypted := decryptCBC(reencrypted, iv, block)
	if !bytes.Equal(plaintext, redecrypted) {
		t.Errorf("expected: %v, got: %v", plaintext, redecrypted)
	}
}

func TestChallenge11(t *testing.T) {
	oracle := newECBCBCOracle()
	input := make([]byte, 16*3)
	for i := range input {
		input[i] = 'A'
	}

	var countECB int
	var countCBC int

	for range 10000 {
		ciphertext := oracle(input)
		block1, block2 := ciphertext[16:16*2], ciphertext[16*2:16*3]
		if bytes.Equal(block1, block2) {
			countECB++
		} else {
			countCBC++
		}
	}

	t.Logf("ECB count: %d, CBC count: %d", countECB, countCBC)
}

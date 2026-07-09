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
	iv := make([]byte, aesBlockSize)
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
	input := bytes.Repeat([]byte{'A'}, 3*aesBlockSize)

	var countECB int
	var countCBC int

	for range 10000 {
		ciphertext := oracle(input)
		block1, block2 := ciphertext[aesBlockSize:aesBlockSize*2], ciphertext[aesBlockSize*2:aesBlockSize*3]
		if bytes.Equal(block1, block2) {
			countECB++
		} else {
			countCBC++
		}
	}

	t.Logf("ECB count: %d, CBC count: %d", countECB, countCBC)
}

func TestChallenge12(t *testing.T) {
	suffix := base64Decode(t, `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
`)
	oracle := newECBSuffixOracle(suffix)
	target := breakECBSuffixOracle(oracle)
	t.Logf("target string: %s", target)
}

func TestChallenge13(t *testing.T) {
	generateCookie, isAdmin := newECBCutAndPasteOracle()

	if isAdmin(generateCookie("")) {
		t.Fatalf("already admin")
	}

	// For the ordering email/uid/role.
	query1 := generateCookie("AAAAAAAAAAadmin")
	block11 := query1[:aesBlockSize]                   // email=AAAAAAAAAA
	block12 := query1[aesBlockSize : 2*aesBlockSize]   // admin&uid=10&rol
	block13 := query1[2*aesBlockSize : 3*aesBlockSize] // e=userPPPPPPPPPP

	query2 := generateCookie("AAAAAAAAAAAAA")
	block22 := query2[aesBlockSize : 2*aesBlockSize] // AAA&uid=10&role=

	// email=AAAAAAAAAA AAA&uid=10&role= admin&uid=10&rol e=userPPPPPPPPPP
	adminCookie1 := block11 + block22 + block12 + block13

	// For the ordering email/role/uid.
	query3 := generateCookie("AAAAAAAAAAadmin")
	query32 := query3[aesBlockSize : 2*aesBlockSize]   // admin&uid=10&rol
	query33 := query3[2*aesBlockSize : 3*aesBlockSize] // e=userPPPPPPPPPP

	query4 := generateCookie("AAAA")
	query41 := query4[:aesBlockSize] // email=AAAA&role=

	// email=AAAA&role= admin&uid=10&rol e=userPPPPPPPPPP
	adminCookie2 := query41 + query32 + query33

	if !isAdmin(adminCookie1) && !isAdmin(adminCookie2) {
		t.Errorf("not an admin")
	}
}

func TestChallenge14(t *testing.T) {
	suffix := base64Decode(t, `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
`)
	oracle := newECBPrefixSuffixOracle(suffix)
	target := breakECBPrefixSuffixOracle(oracle)
	t.Logf("target string: %s", target)
}

func TestChallenge15(t *testing.T) {
	expected := "ICE ICE BABY"
	if unpadded := unpadPKCS7([]byte("ICE ICE BABY\x04\x04\x04\x04")); string(unpadded) != "ICE ICE BABY" {
		t.Errorf("expected %s, got %s", expected, unpadded)
	}

	if unpadded := unpadPKCS7([]byte("ICE ICE BABY\x05\x05\x05\x05")); unpadded != nil {
		t.Errorf("expected nil, got %s", unpadded)
	}

	if unpadded := unpadPKCS7([]byte("ICE ICE BABY\x01\x02\x03\x04")); unpadded != nil {
		t.Errorf("expected nil, got %s", unpadded)
	}
}

func TestChallenge16(t *testing.T) {
	generateCookie, isAdmin := newCBCCookieOracle()

	if isAdmin(generateCookie("")) {
		t.Fatalf("already admin")
	}

	query := "AadminAtrueAAAAA"
	cookie := generateCookie(query)
	attack := []byte(cookie)
	attack[aesBlockSize+0] ^= query[0] ^ ';'
	attack[aesBlockSize+6] ^= query[6] ^ '='
	attack[aesBlockSize+11] ^= query[11] ^ ';'

	if !isAdmin(string(attack)) {
		t.Errorf("not an admin")
	}
}

package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
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

func TestChallenge27(t *testing.T) {
	encrypt, decrypt, checkKey := newCBCSharedKeyIVOracle()
	key := breakCBCSharedKeyIVOracle(encrypt, decrypt)
	if !checkKey(key) {
		t.Errorf("incorrect key: %v", key)
	}
}

func TestChallenge28(t *testing.T) {
	for _, tt := range []struct {
		input   string
		hashHex string
	}{
		{
			input:   "abc",
			hashHex: "a9993e364706816aba3e25717850c26c9cd0d89d",
		},
		{
			input:   "",
			hashHex: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			input:   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			hashHex: "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
		},
		{
			input:   "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			hashHex: "a49b2446a02c645bf419f995b67091253a04a259",
		},
	} {
		t.Run(tt.input, func(t *testing.T) {
			expectedDigest, err := hex.DecodeString(tt.hashHex)
			if err != nil {
				t.Fatal(err)
			}
			if len(expectedDigest) != sha1Size {
				t.Fatalf("expected hash length %d, got %d", sha1Size, len(expectedDigest))
			}

			sha1 := newSHA1()
			n, err := sha1.Write([]byte(tt.input))
			if err != nil {
				t.Errorf("SHA-1 write: %v", err)
			}
			if n != len(tt.input) {
				t.Errorf("SHA-1 partial write: expected %d bytes, got %d", len(tt.input), n)
			}

			digest := sha1.digest()
			if !bytes.Equal(digest[:], expectedDigest) {
				t.Errorf("expected digest: %v, got %v", expectedDigest, digest)
			}
		})
	}

	key := make([]byte, aesBlockSize)
	rand.Read(key)

	msg := []byte("abcdefgh")
	digest1 := newKeyedSHA1(key, msg)
	msg[0] = 'b'
	digest2 := newKeyedSHA1(key, msg)

	if digest1 == digest2 {
		t.Errorf("keyed digests equal for different messages: %v == %v", digest1, digest2)
	}
}

func TestChallenge29(t *testing.T) {
	msg := []byte("hello, cryptopals!")

	sha1A := newSHA1()
	sha1A.Write(msg)
	sha1A.digest()

	sha1B := newSHA1()
	sha1B.Write(msg)
	sha1B.Write(padSHA1(len(msg)))

	if sha1A.nx != 0 {
		t.Fatal("sha1A nx != 0")
	}
	if sha1A.h != sha1B.h {
		t.Fatalf("expected the same states for unpadded and padded messages, got %v and %v", sha1A.h, sha1B.h)
	}

	cookie, isAdmin := newKeyedSHA1CookieOracle()
	if isAdmin(cookie) {
		t.Fatalf("already admin")
	}

	found := false
	for keySize := 2; keySize < 101; keySize++ {
		adminCookie := breakKeyedSHA1CookieOracle(cookie, keySize)
		if isAdmin(adminCookie) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("not an admin")
	}
}

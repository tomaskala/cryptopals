package cryptopals

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"math/big"
	mathrand "math/rand/v2"
)

func newRSAUnpaddedMessageRecoveryOracle(bits int) (
	pub *rsa.PublicKey,
	encrypt func([]byte) []byte,
	decrypt func([]byte) []byte,
) {
	key := rsaGenerate(bits)
	seenCiphertexts := make(map[[sha256.Size]byte]struct{})

	pub = &key.PublicKey
	encrypt = func(plaintext []byte) []byte {
		return rsaEncrypt(plaintext, &key.PublicKey)
	}
	decrypt = func(ciphertext []byte) []byte {
		h := sha256.Sum256(ciphertext)
		if _, ok := seenCiphertexts[h]; ok {
			return nil
		}
		seenCiphertexts[h] = struct{}{}
		return rsaDecrypt(ciphertext, key)
	}
	return
}

func breakRSAUnpaddedMessageRecoveryOracle(ciphertext []byte, key *rsa.PublicKey, decrypt func([]byte) []byte) []byte {
	s := big.NewInt(2 + mathrand.N[int64](1023))

	c := new(big.Int).Exp(s, big.NewInt(int64(key.E)), key.N)
	c.Mul(c, new(big.Int).SetBytes(ciphertext))
	c.Mod(c, key.N)

	p := decrypt(c.Bytes())

	plaintext := new(big.Int).SetBytes(p)
	plaintext.Mul(plaintext, new(big.Int).ModInverse(s, key.N))
	plaintext.Mod(plaintext, key.N)
	return plaintext.Bytes()
}

// Taken from https://github.com/golang/go/blob/c9e2d9eb06d2c57cb2a78707fb60a639a94efb42/src/crypto/rsa/pkcs1v15.go#L250
var pkcs1v15SHA1ASN1 = []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}

func newRSASignatureOracle(bits int) func([]byte, []byte) bool {
	key := rsaGenerate(bits)
	pub := &key.PublicKey
	check := func(msg []byte, pos int, expected byte) bool {
		if pos < 0 || pos >= len(msg) {
			return false
		}
		return msg[pos] == expected
	}

	return func(msg, sig []byte) bool {
		// 0x00 0x01 0xff ... 0xff 0x00 ASN.1 HASH
		m := rsaEncrypt(sig, pub)

		// The heading 0x00 check is omitted, because number conversion loses it entirely.
		if !check(m, 0, 0x01) {
			return false
		}

		i := 1
		for i < len(m) && m[i] == 0xff {
			i++
		}

		if !check(m, i, 0x00) {
			return false
		}
		i++

		for _, val := range pkcs1v15SHA1ASN1 {
			if !check(m, i, val) {
				return false
			}
			i++
		}

		h := sha1.Sum(msg)
		hash := m[i : i+len(h)]
		return bytes.Equal(hash, h[:])
	}
}

func forgeRSASignature(msg []byte, keySizeBits int) []byte {
	keySizeBytes := keySizeBits / 8
	s := make([]byte, keySizeBytes)
	i := 0
	insert := func(val byte) {
		s[i] = val
		i++
	}

	// Insert the 0x00 0x01 header.
	insert(0x00)
	insert(0x01)

	// Insert the minimum amount of padding.
	for range 8 {
		insert(0xff)
	}

	// Insert the 0x00 separator.
	insert(0x00)

	// Insert ASN.1
	for _, val := range pkcs1v15SHA1ASN1 {
		insert(val)
	}

	// Insert HASH
	h := sha1.Sum(msg)
	for _, val := range h {
		insert(val)
	}

	sig := new(big.Int).SetBytes(s)
	return integerCubeRoot(sig).Bytes()
}

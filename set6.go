package cryptopals

import (
	"crypto/rsa"
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

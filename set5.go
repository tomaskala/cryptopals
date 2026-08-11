package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
	"math/big"
)

var p, _ = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)

type dhParams struct {
	g *big.Int
	p *big.Int
}

func (dh dhParams) genPrivate() *big.Int {
	r, err := rand.Int(rand.Reader, dh.p)
	if err != nil {
		panic(err)
	}
	return r
}

func (dh dhParams) genPublic(private *big.Int) *big.Int {
	return new(big.Int).Exp(dh.g, private, dh.p)
}

func (dh dhParams) genSecret(private, public *big.Int) *big.Int {
	return new(big.Int).Exp(public, private, dh.p)
}

type echoPeer struct {
	private *big.Int
	key     []byte
	iv      []byte
}

func newEchoPeer(dh dhParams) *echoPeer {
	iv := make([]byte, aesBlockSize)
	rand.Read(iv)
	return &echoPeer{private: dh.genPrivate(), iv: iv}
}

func (p *echoPeer) deriveSecret(dh dhParams, public *big.Int) {
	secret := dh.genSecret(p.private, public)
	sha1 := newSHA1()
	_, err := sha1.Write(secret.Bytes())
	if err != nil {
		panic(err)
	}
	digest := sha1.digest()
	p.key = digest[:aesBlockSize]
}

func (p *echoPeer) encrypt(msg []byte) []byte {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		panic(err)
	}
	ciphertext := encryptCBC(p.iv, padPKCS7(msg, aesBlockSize), block)
	return append(ciphertext, p.iv...)
}

func (p *echoPeer) decrypt(msg []byte) []byte {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		panic(err)
	}
	ciphertext, iv := msg[:len(msg)-aesBlockSize], msg[len(msg)-aesBlockSize:]
	decrypted := decryptCBC(iv, ciphertext, block)
	return unpadPKCS7(decrypted)
}

func createEchoBot(dh dhParams) (*echoPeer, *echoPeer) {
	alice := newEchoPeer(dh)
	bob := newEchoPeer(dh)

	A := dh.genPublic(alice.private)
	bob.deriveSecret(dh, A)

	B := dh.genPublic(bob.private)
	alice.deriveSecret(dh, B)

	return alice, bob
}

func createMITMEchoBot(dh dhParams) (*echoPeer, *echoPeer, *echoPeer) {
	alice := newEchoPeer(dh)
	bob := newEchoPeer(dh)
	eve := newEchoPeer(dh)

	E := dh.p

	bob.deriveSecret(dh, E)
	eve.deriveSecret(dh, big.NewInt(0))
	alice.deriveSecret(dh, E)

	return alice, eve, bob
}

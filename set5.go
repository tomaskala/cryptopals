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

func (p *echoPeer) initKey(dh dhParams, public *big.Int) {
	secret := dh.genSecret(p.private, public)
	p.key = deriveKey(secret)
}

func deriveKey(secret *big.Int) []byte {
	sha1 := newSHA1()
	_, err := sha1.Write(secret.Bytes())
	if err != nil {
		panic(err)
	}
	digest := sha1.digest()
	return digest[:aesBlockSize]
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
	bob.initKey(dh, A)

	B := dh.genPublic(bob.private)
	alice.initKey(dh, B)

	return alice, bob
}

func createMITMEchoBot(dh dhParams) (*echoPeer, *echoPeer, *echoPeer) {
	alice := newEchoPeer(dh)
	bob := newEchoPeer(dh)
	eve := newEchoPeer(dh)

	E := dh.p

	bob.initKey(dh, E)
	eve.key = deriveKey(big.NewInt(0))
	alice.initKey(dh, E)

	return alice, eve, bob
}

func createMITMEchoBotG1(dh dhParams) (*echoPeer, *echoPeer, *echoPeer) {
	dh.g = big.NewInt(1)

	alice := newEchoPeer(dh)
	bob := newEchoPeer(dh)
	eve := newEchoPeer(dh)

	A := dh.genPublic(alice.private)
	bob.initKey(dh, A)

	B := dh.genPublic(bob.private)
	alice.initKey(dh, B)

	eve.key = deriveKey(big.NewInt(1))

	return alice, eve, bob
}

func createMITMEchoBotGp(dh dhParams) (*echoPeer, *echoPeer, *echoPeer) {
	dh.g = dh.p

	alice := newEchoPeer(dh)
	bob := newEchoPeer(dh)
	eve := newEchoPeer(dh)

	A := dh.genPublic(alice.private)
	bob.initKey(dh, A)

	B := dh.genPublic(bob.private)
	alice.initKey(dh, B)

	eve.key = deriveKey(big.NewInt(0))

	return alice, eve, bob
}

func createMITMEchoBotGpm1(dh dhParams) (*echoPeer, *echoPeer, *echoPeer) {
	dh.g = new(big.Int).Sub(dh.p, big.NewInt(1))

	alice := newEchoPeer(dh)
	bob := newEchoPeer(dh)
	eve := newEchoPeer(dh)

	A := dh.genPublic(alice.private)
	bob.initKey(dh, A)

	B := dh.genPublic(bob.private)
	alice.initKey(dh, B)

	eve.key = deriveKey(big.NewInt(1))

	probe := []byte("test message")
	encrypted := alice.encrypt(probe)
	if eve.decrypt(encrypted) == nil {
		eve.key = deriveKey(new(big.Int).Sub(p, big.NewInt(1)))
	}

	return alice, eve, bob
}

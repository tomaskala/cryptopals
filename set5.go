package cryptopals

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

var srpK = big.NewInt(3)

type srpVerifier struct {
	salt []byte
	v    *big.Int
}

type srpSession struct {
	email string
	key   []byte
	salt  []byte
}

type srpServer struct {
	dh          dhParams
	credentials map[string]srpVerifier
	sessions    map[string]*srpSession
}

func newSRPServer(dh dhParams) *srpServer {
	return &srpServer{
		dh:          dh,
		credentials: make(map[string]srpVerifier),
		sessions:    make(map[string]*srpSession),
	}
}

// register represents a POST /register endpoint.
func (s *srpServer) register(email string, credentials srpVerifier) {
	s.credentials[email] = credentials
}

// exchange represents a POST /sessions endpoint.
func (s *srpServer) exchange(email string, A *big.Int) (string, []byte, *big.Int) {
	user := s.credentials[email]
	b := s.dh.genPrivate()

	// B = (k*v + g^b) mod p
	B := new(big.Int)
	B.Mul(srpK, user.v)
	B.Add(B, s.dh.genPublic(b))
	B.Mod(B, s.dh.p)

	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	// S = (A * v^u)^b mod p
	S := new(big.Int)
	S.Exp(user.v, u, s.dh.p)
	S.Mul(S, A)
	S.Exp(S, b, s.dh.p)

	K := sha256.Sum256(S.Bytes())

	sid := make([]byte, 16)
	rand.Read(sid)
	sessionID := hex.EncodeToString(sid)
	s.sessions[sessionID] = &srpSession{
		email: email,
		key:   K[:],
		salt:  user.salt,
	}

	return sessionID, user.salt, B
}

// validate represents a POST /sessions/{id}/proof endpoint.
func (s *srpServer) validate(sessionID string, mac []byte) bool {
	session := s.sessions[sessionID]
	h := hmac.New(sha256.New, session.key)
	h.Write(session.salt)
	return hmac.Equal(h.Sum(nil), mac)
}

type srpClient struct {
	dh    dhParams
	email string
}

func newSRPClient(dh dhParams, email string) *srpClient {
	return &srpClient{dh: dh, email: email}
}

func (c *srpClient) deriveCredentials(password []byte) srpVerifier {
	salt := make([]byte, 16)
	rand.Read(salt)

	xH := sha256.Sum256(append(salt, password...))
	x := new(big.Int).SetBytes(xH[:])

	// v = g^x mod p
	v := new(big.Int).Exp(c.dh.g, x, c.dh.p)

	return srpVerifier{salt: salt, v: v}
}

func (c *srpClient) login(server *srpServer, password []byte) bool {
	a := c.dh.genPrivate()
	A := c.dh.genPublic(a)
	sessionID, salt, B := server.exchange(c.email, A)

	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	xH := sha256.Sum256(append(salt, password...))
	x := new(big.Int).SetBytes(xH[:])

	// exp = (a + u*x) mod p
	exp := new(big.Int)
	exp.Mul(u, x)
	exp.Add(exp, a)
	exp.Mod(exp, c.dh.p)

	// S = (B - k*g^x)^exp mod p
	S := new(big.Int)
	S.Exp(c.dh.g, x, c.dh.p)
	S.Mul(srpK, S)
	S.Sub(B, S)
	S.Exp(S, exp, c.dh.p)

	K := sha256.Sum256(S.Bytes())
	h := hmac.New(sha256.New, K[:])
	h.Write(salt)
	mac := h.Sum(nil)

	return server.validate(sessionID, mac)
}

func bypassLogin(email string, server *srpServer) bool {
	A := big.NewInt(0)
	sessionID, salt, _ := server.exchange(email, A)

	K := sha256.Sum256(nil)
	h := hmac.New(sha256.New, K[:])
	h.Write(salt)
	mac := h.Sum(nil)

	return server.validate(sessionID, mac)
}

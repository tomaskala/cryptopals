package cryptopals

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

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
		eve.key = deriveKey(new(big.Int).Sub(dh.p, big.NewInt(1)))
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

type srpServer interface {
	// register represents a POST /register endpoint.
	register(string, srpVerifier)

	// exchange represents a POST /sessions endpoint.
	exchange(string, *big.Int) (string, []byte, *big.Int)

	// validate represents a POST /sessions/{id}/proof endpoint.
	validate(string, []byte) bool
}

type srpRealServer struct {
	dh          dhParams
	credentials map[string]srpVerifier
	sessions    map[string]*srpSession
}

func newRealSRPServer(dh dhParams) *srpRealServer {
	return &srpRealServer{
		dh:          dh,
		credentials: make(map[string]srpVerifier),
		sessions:    make(map[string]*srpSession),
	}
}

func (s *srpRealServer) register(email string, credentials srpVerifier) {
	s.credentials[email] = credentials
}

func (s *srpRealServer) exchange(email string, A *big.Int) (string, []byte, *big.Int) {
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

func (s *srpRealServer) validate(sessionID string, mac []byte) bool {
	session := s.sessions[sessionID]
	h := hmac.New(sha256.New, session.key)
	h.Write(session.salt)
	return hmac.Equal(h.Sum(nil), mac)
}

func deriveCredentials(dh dhParams, password []byte) srpVerifier {
	salt := make([]byte, 16)
	rand.Read(salt)

	xH := sha256.Sum256(append(salt, password...))
	x := new(big.Int).SetBytes(xH[:])

	// v = g^x mod p
	v := new(big.Int).Exp(dh.g, x, dh.p)

	return srpVerifier{salt: salt, v: v}
}

type srpRealClient struct {
	dh       dhParams
	email    string
	password []byte
}

func newRealSRPClient(dh dhParams, email string, password []byte) *srpRealClient {
	return &srpRealClient{dh: dh, email: email, password: password}
}

func (c *srpRealClient) login(server srpServer) bool {
	a := c.dh.genPrivate()
	A := c.dh.genPublic(a)
	sessionID, salt, B := server.exchange(c.email, A)

	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	xH := sha256.Sum256(append(salt, c.password...))
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

type srpSimplifiedClient struct {
	dh       dhParams
	email    string
	password []byte
}

func newSimplifiedSRPClient(dh dhParams, email string, password []byte) *srpSimplifiedClient {
	return &srpSimplifiedClient{dh: dh, email: email, password: password}
}

func (c *srpSimplifiedClient) login(server srpServer) bool {
	a := c.dh.genPrivate()
	A := c.dh.genPublic(a)
	sessionID, salt, B := server.exchange(c.email, A)

	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	xH := sha256.Sum256(append(salt, c.password...))
	x := new(big.Int).SetBytes(xH[:])

	// exp = (a + u*x) mod p
	exp := new(big.Int)
	exp.Mul(u, x)
	exp.Add(exp, a)
	exp.Mod(exp, c.dh.p)

	// S = B^exp mod p
	S := new(big.Int)
	S.Exp(B, exp, c.dh.p)

	K := sha256.Sum256(S.Bytes())
	h := hmac.New(sha256.New, K[:])
	h.Write(salt)
	mac := h.Sum(nil)

	return server.validate(sessionID, mac)
}

type srpSimplifiedServer struct {
	dh          dhParams
	credentials map[string]srpVerifier
	sessions    map[string]*srpSession
}

func newSimplifiedSRPServer(dh dhParams) *srpSimplifiedServer {
	return &srpSimplifiedServer{
		dh:          dh,
		credentials: make(map[string]srpVerifier),
		sessions:    make(map[string]*srpSession),
	}
}

func (s *srpSimplifiedServer) register(email string, credentials srpVerifier) {
	s.credentials[email] = credentials
}

func (s *srpSimplifiedServer) exchange(email string, A *big.Int) (string, []byte, *big.Int) {
	user := s.credentials[email]
	b := s.dh.genPrivate()

	// B = g^b mod p
	B := s.dh.genPublic(b)

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

func (s *srpSimplifiedServer) validate(sessionID string, mac []byte) bool {
	session := s.sessions[sessionID]
	h := hmac.New(sha256.New, session.key)
	h.Write(session.salt)
	return hmac.Equal(h.Sum(nil), mac)
}

func bypassLogin(email string, server *srpRealServer) bool {
	A := big.NewInt(0)
	sessionID, salt, _ := server.exchange(email, A)

	K := sha256.Sum256(nil)
	h := hmac.New(sha256.New, K[:])
	h.Write(salt)
	mac := h.Sum(nil)

	return server.validate(sessionID, mac)
}

type srpMITMServer struct {
	dh   dhParams
	b    *big.Int
	B    *big.Int
	salt []byte

	capturedMAC []byte
	A           *big.Int
}

func newMITMSRPServer(dh dhParams) *srpMITMServer {
	b := dh.genPrivate()
	B := dh.genPublic(b)
	salt := make([]byte, 16)
	rand.Read(salt)
	return &srpMITMServer{dh: dh, b: b, B: B, salt: salt}
}

func (s *srpMITMServer) register(email string, credentials srpVerifier) {
}

func (s *srpMITMServer) exchange(email string, A *big.Int) (string, []byte, *big.Int) {
	s.A = A
	return "", s.salt, s.B
}

func (s *srpMITMServer) validate(sessionID string, mac []byte) bool {
	s.capturedMAC = mac
	return true
}

func (s *srpMITMServer) tryPassword(password []byte) bool {
	uH := sha256.Sum256(append(s.A.Bytes(), s.B.Bytes()...))
	u := new(big.Int).SetBytes(uH[:])

	buf := append([]byte(nil), s.salt...)
	buf = append(buf, password...)
	xH := sha256.Sum256(buf)
	x := new(big.Int).SetBytes(xH[:])

	// S = A^b * B^(u*x) mod p
	exp := new(big.Int)
	exp.Mul(u, x)

	S := new(big.Int)
	S.Exp(s.B, exp, s.dh.p)
	S.Mul(S, s.dh.genSecret(s.b, s.A))
	S.Mod(S, s.dh.p)

	K := sha256.Sum256(S.Bytes())
	h := hmac.New(sha256.New, K[:])
	h.Write(s.salt)

	return hmac.Equal(h.Sum(nil), s.capturedMAC)
}

func rsaGenerate(bits int) *rsa.PrivateKey {
	const e = 3
	bigE := big.NewInt(e)
	big1 := big.NewInt(1)

	genPrime := func() (*big.Int, *big.Int) {
		for {
			p, err := rand.Prime(rand.Reader, bits)
			if err != nil {
				panic(err)
			}
			pm1 := new(big.Int).Sub(p, big1)
			if new(big.Int).GCD(nil, nil, pm1, bigE).Cmp(big1) == 0 {
				return p, pm1
			}
		}
	}

	p, pm1 := genPrime()
	q, qm1 := genPrime()
	n := new(big.Int).Mul(p, q)
	et := new(big.Int).Mul(pm1, qm1)
	d := new(big.Int).ModInverse(bigE, et)

	return &rsa.PrivateKey{
		N:      n,
		E:      e,
		D:      d,
		Primes: []*big.Int{p, q},
	}
}

func rsaEncrypt(plaintext []byte, key *rsa.PublicKey) []byte {
	m := new(big.Int).SetBytes(plaintext)
	if m.Cmp(key.N) >= 0 {
		panic("message too large")
	}
	c := new(big.Int).Exp(m, big.NewInt(int64(key.E)), key.N)
	return c.Bytes()
}

func rsaDecrypt(ciphertext []byte, key *rsa.PrivateKey) []byte {
	m := new(big.Int).SetBytes(ciphertext)
	if m.Cmp(key.N) >= 0 {
		panic("message too large")
	}
	d := new(big.Int).Exp(m, key.D, key.N)
	return d.Bytes()
}

func rsaBroadcastAttack(c [3]*big.Int, key [3]*rsa.PublicKey) *big.Int {
	for i := range len(key) {
		if key[i].E != 3 {
			panic("can only break E=3 public keys")
		}
	}

	for i := range len(key) {
		for j := range len(key) {
			if i == j {
				continue
			}

			gcd := new(big.Int).GCD(nil, nil, key[i].N, key[j].N)
			if gcd.Cmp(big.NewInt(1)) != 0 {
				panic("public key moduli are not pairwise coprime")
			}
		}
	}

	m := [...]*big.Int{
		new(big.Int).Mul(key[1].N, key[2].N),
		new(big.Int).Mul(key[0].N, key[2].N),
		new(big.Int).Mul(key[0].N, key[1].N),
	}

	n := big.NewInt(1)
	n.Mul(n, key[0].N)
	n.Mul(n, key[1].N)
	n.Mul(n, key[2].N)

	mCubed := new(big.Int)
	for i := range len(c) {
		term := big.NewInt(1)
		term.Mul(term, c[i])
		term.Mul(term, m[i])
		term.Mul(term, new(big.Int).ModInverse(m[i], key[i].N))
		mCubed.Add(mCubed, term)
	}
	mCubed.Mod(mCubed, n)

	return integerCubeRoot(mCubed)
}

func integerCubeRoot(n *big.Int) *big.Int {
	low := big.NewInt(0)
	high := new(big.Int).Set(n)
	big1 := big.NewInt(1)
	big2 := big.NewInt(2)

	for low.Cmp(high) < 0 {
		mid := new(big.Int).Add(low, high)
		mid.Div(mid, big2)

		cube := new(big.Int).Mul(mid, mid)
		cube.Mul(cube, mid)

		if cube.Cmp(n) < 0 {
			low.Add(mid, big1)
		} else {
			high.Set(mid)
		}
	}

	return low
}

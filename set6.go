package cryptopals

import (
	"bytes"
	"crypto/rand"
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

type dsaParameters struct {
	p *big.Int
	q *big.Int
	g *big.Int
}

func mustSetHexString(s string) *big.Int {
	num, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("cannot set string")
	}
	return num
}

var cryptopalsDSAParams = dsaParameters{
	p: mustSetHexString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"),
	q: mustSetHexString("f4f47f05794b256174bba6e9b396a7707e563c5b"),
	g: mustSetHexString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291"),
}

func (dsa dsaParameters) generate() (*big.Int, *big.Int) {
	big1 := big.NewInt(1)
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(dsa.q, big1))
	if err != nil {
		panic(err)
	}
	x.Add(x, big1)
	y := new(big.Int).Exp(dsa.g, x, dsa.p)
	return x, y
}

func (dsa dsaParameters) sign(x *big.Int, msg []byte) (*big.Int, *big.Int) {
	big0 := big.NewInt(0)
	big1 := big.NewInt(1)

	for {
		k, err := rand.Int(rand.Reader, new(big.Int).Sub(dsa.q, big1))
		if err != nil {
			panic(err)
		}

		r := new(big.Int).Exp(dsa.g, k, dsa.p)
		r.Mod(r, dsa.q)
		if r.Cmp(big0) == 0 {
			continue
		}

		digest := sha1.Sum(msg)
		h := new(big.Int).SetBytes(digest[:])
		kInv := new(big.Int).ModInverse(k, dsa.q)

		s := new(big.Int).Mul(x, r)
		s.Add(s, h)
		s.Mul(s, kInv)
		s.Mod(s, dsa.q)
		if s.Cmp(big0) == 0 {
			continue
		}
		return r, s
	}
}

func (dsa dsaParameters) verify(y, r, s *big.Int, msg []byte) bool {
	big0 := big.NewInt(0)
	if r.Cmp(big0) < 0 || r.Cmp(dsa.q) >= 0 {
		return false
	}
	if s.Cmp(big0) < 0 || s.Cmp(dsa.q) >= 0 {
		return false
	}

	w := new(big.Int).ModInverse(s, dsa.q)
	digest := sha1.Sum(msg)
	h := new(big.Int).SetBytes(digest[:])

	u1 := new(big.Int).Mul(h, w)
	u1.Mod(u1, dsa.q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, dsa.q)

	exp1 := new(big.Int).Exp(dsa.g, u1, dsa.p)
	exp2 := new(big.Int).Exp(y, u2, dsa.p)
	v := new(big.Int).Mul(exp1, exp2)
	v.Mod(v, dsa.p)
	v.Mod(v, dsa.q)

	return v.Cmp(r) == 0
}

func calculatePrivateKey(q, h, r, s, k *big.Int) *big.Int {
	rInv := new(big.Int).ModInverse(r, q)
	x := new(big.Int).Mul(s, k)
	x.Sub(x, h)
	x.Mul(x, rInv)
	x.Mod(x, q)
	return x
}

func recoverDSAPrivateKeyFromSmallNonce(dsa dsaParameters, y, r, s *big.Int, msg []byte) *big.Int {
	digest := sha1.Sum(msg)
	h := new(big.Int).SetBytes(digest[:])

	// A slower method that calculates a candidate private key for each possible k,
	// uses it to calculate a public key, and compares it with the known public key.
	/*
		k := big.NewInt(0)
		big1 := big.NewInt(1)

		for k.BitLen() <= 16 {
			possibleX := calculatePrivateKey(dsa.q, h, r, s, k)
			possibleY := new(big.Int).Exp(dsa.g, possibleX, dsa.p)
			if possibleY.Cmp(y) == 0 {
				return possibleX
			}
			k.Add(k, big1)
		}
	*/

	// A faster method that calculates a candidate r parameter for each possible k,
	// compares it with the known parameter r, and calculates a private key from the
	// k for which r matched.
	k := big.NewInt(0)
	big1 := big.NewInt(1)
	possibleRTerm := big.NewInt(1)
	possibleR := big.NewInt(1)

	for k.BitLen() <= 16 {
		if possibleR.Cmp(r) == 0 {
			return calculatePrivateKey(dsa.q, h, r, s, k)
		}
		possibleRTerm.Mul(possibleRTerm, dsa.g)
		possibleRTerm.Mod(possibleRTerm, dsa.p)
		possibleR.Mod(possibleRTerm, dsa.q)
		k.Add(k, big1)
	}

	return nil
}

func recoverDSAPrivateKeyFromRepeatedNonce(dsa dsaParameters, r, s1, s2 *big.Int, msg1, msg2 []byte) *big.Int {
	digest1 := sha1.Sum(msg1)
	h1 := new(big.Int).SetBytes(digest1[:])

	digest2 := sha1.Sum(msg2)
	h2 := new(big.Int).SetBytes(digest2[:])

	hDiff := new(big.Int).Sub(h1, h2)
	sDiff := new(big.Int).Sub(s1, s2)
	sDiffInv := new(big.Int).ModInverse(sDiff, dsa.q)
	k := new(big.Int).Mul(hDiff, sDiffInv)

	return calculatePrivateKey(dsa.q, h1, r, s1, k)
}

func magicDSASignatureForG1(p, q, y *big.Int) (*big.Int, *big.Int) {
	z := big.NewInt(1337)
	zInv := new(big.Int).ModInverse(z, q)

	r := new(big.Int).Exp(y, z, p)
	r.Mod(r, q)

	s := new(big.Int).Mul(r, zInv)
	s.Mod(s, q)

	return r, s
}

func newRSAParityOracle(bits int) (
	pub *rsa.PublicKey,
	encrypt func([]byte) []byte,
	isPlaintextEven func([]byte) bool,
) {
	key := rsaGenerate(bits)
	big0 := big.NewInt(0)
	big2 := big.NewInt(2)

	pub = &key.PublicKey
	encrypt = func(plaintext []byte) []byte {
		return rsaEncrypt(plaintext, pub)
	}
	isPlaintextEven = func(ciphertext []byte) bool {
		plaintext := rsaDecrypt(ciphertext, key)
		n := new(big.Int).SetBytes(plaintext)
		parity := n.Mod(n, big2)
		return parity.Cmp(big0) == 0
	}
	return
}

func breakRSAParityOracle(pub *rsa.PublicKey, ciphertext []byte, isPlaintextEven func([]byte) bool) []byte {
	big2 := big.NewInt(2)
	bigE := big.NewInt(int64(pub.E))
	enc2 := new(big.Int).Exp(big2, bigE, pub.N)

	c := new(big.Int).SetBytes(ciphertext)

	low := new(big.Rat).SetInt64(0)
	high := new(big.Rat).SetInt(pub.N)
	two := new(big.Rat).SetInt64(2)

	for range pub.N.BitLen() {
		c.Mul(c, enc2)
		c.Mod(c, pub.N)

		mid := new(big.Rat).Add(low, high)
		mid.Quo(mid, two)

		if isPlaintextEven(c.Bytes()) {
			high.Set(mid)
		} else {
			low.Set(mid)
		}
	}

	result := new(big.Int).Div(high.Num(), high.Denom())
	return result.Bytes()
}

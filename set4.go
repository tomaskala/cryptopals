package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	mathrand "math/rand/v2"
	"regexp"
	"strings"
	"time"
)

func newRandomAccessCTROracle() (
	encrypt func([]byte) []byte,
	edit func([]byte, int, []byte) []byte,
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	nonce := make([]byte, aesBlockSize/2)
	rand.Read(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encrypt = func(plaintext []byte) []byte {
		return append(nonce, encryptCTR(nonce, plaintext, block)...)
	}
	edit = func(ciphertext []byte, offset int, newText []byte) []byte {
		nonce := ciphertext[:aesBlockSize/2]
		bs := ciphertext[aesBlockSize/2:]

		plaintext := decryptCTR(nonce, bs, block)
		copy(plaintext[offset:], newText)

		return encrypt(plaintext)
	}
	return
}

func breakRandomAccessCTR(ciphertext []byte, edit func([]byte, int, []byte) []byte) []byte {
	var plaintext []byte
	for offset := aesBlockSize / 2; offset < len(ciphertext); offset++ {
		newCiphertext := edit(ciphertext, offset-aesBlockSize/2, []byte{'A'})
		plaintext = append(plaintext, ciphertext[offset]^newCiphertext[offset]^'A')
	}
	return plaintext
}

func newCTRCookieOracle() (
	generateCookie func(string) string,
	isAdmin func(string) bool,
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	nonce := make([]byte, aesBlockSize/2)
	rand.Read(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	generateCookie = func(input string) string {
		sanitized := strings.ReplaceAll(input, ";", "")
		sanitized = strings.ReplaceAll(sanitized, "=", "")
		cookie := prefix + sanitized + suffix
		return string(encryptCTR(nonce, []byte(cookie), block))
	}
	isAdmin = func(s string) bool {
		buf := decryptCTR(nonce, []byte(s), block)
		return strings.Contains(string(buf), ";admin=true;")
	}
	return
}

var printableASCII = regexp.MustCompile("^[ -~]+$")

func newCBCSharedKeyIVOracle() (
	encryptMessage func([]byte) []byte,
	decryptMessage func([]byte) error,
	checkKey func([]byte) bool,
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encryptMessage = func(bs []byte) []byte {
		buf := padPKCS7(bs, aesBlockSize)
		return encryptCBC(key, buf, block)
	}
	decryptMessage = func(bs []byte) error {
		buf := unpadPKCS7(decryptCBC(key, bs, block))
		if !printableASCII.Match(buf) {
			return fmt.Errorf("invalid message: %s", buf)
		}
		return nil
	}
	checkKey = func(bs []byte) bool {
		return bytes.Equal(bs, key)
	}
	return
}

func breakCBCSharedKeyIVOracle(encrypt func([]byte) []byte, decrypt func([]byte) error) []byte {
	msg := bytes.Repeat([]byte{'A'}, 4*aesBlockSize)
	ciphertext := encrypt(msg)

	for i := range aesBlockSize {
		ciphertext[aesBlockSize+i] = 0x00
		ciphertext[2*aesBlockSize+i] = ciphertext[i]
	}

	err := decrypt(ciphertext)
	if err == nil {
		return nil
	}

	plaintext := []byte(strings.TrimPrefix(err.Error(), "invalid message: "))
	p1 := plaintext[:aesBlockSize]
	p3 := plaintext[2*aesBlockSize : 3*aesBlockSize]
	return fixedXOR(p1, p3)
}

const (
	sha1Size  = 20
	sha1Chunk = 64

	sha1Init0 = 0x67452301
	sha1Init1 = 0xEFCDAB89
	sha1Init2 = 0x98BADCFE
	sha1Init3 = 0x10325476
	sha1Init4 = 0xC3D2E1F0

	sha1K0 = 0x5A827999
	sha1K1 = 0x6ED9EBA1
	sha1K2 = 0x8F1BBCDC
	sha1K3 = 0xCA62C1D6
)

type sha1State struct {
	h      [5]uint32
	x      [sha1Chunk]byte
	nx     int
	length uint64
}

func newSHA1() *sha1State {
	s := new(sha1State)
	s.reset()
	return s
}

func (s *sha1State) reset() {
	s.h[0] = sha1Init0
	s.h[1] = sha1Init1
	s.h[2] = sha1Init2
	s.h[3] = sha1Init3
	s.h[4] = sha1Init4
	s.nx = 0
	s.length = 0
}

func (s *sha1State) Write(p []byte) (nn int, err error) {
	nn = len(p)
	s.length += uint64(nn)
	if s.nx > 0 {
		n := copy(s.x[s.nx:], p)
		s.nx += n
		if s.nx == sha1Chunk {
			s.block(s.x[:])
			s.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= sha1Chunk {
		n := len(p) &^ (sha1Chunk - 1)
		s.block(p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		s.nx = copy(s.x[:], p)
	}
	return
}

func (s *sha1State) block(p []byte) {
	var w [16]uint32

	h0, h1, h2, h3, h4 := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4]
	for len(p) >= sha1Chunk {
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := range 16 {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		// Each of the four 20-iteration rounds
		// differs only in the computation of f and
		// the choice of K (_K0, _K1, etc).
		i := 0
		for ; i < 16; i++ {
			f := b&c | (^b)&d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K0
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 20; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)

			f := b&c | (^b)&d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K0
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 40; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)
			f := b ^ c ^ d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K1
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 60; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)
			f := ((b | c) & d) | (b & c)
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K2
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}
		for ; i < 80; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = bits.RotateLeft32(tmp, 1)
			f := b ^ c ^ d
			t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K3
			a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e

		p = p[sha1Chunk:]
	}

	s.h[0], s.h[1], s.h[2], s.h[3], s.h[4] = h0, h1, h2, h3, h4
}

func (s *sha1State) digest() [sha1Size]byte {
	length := s.length
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if length%64 < 56 {
		t = 56 - length%64
	} else {
		t = 64 + 56 - length%64
	}

	// Length in bits.
	length <<= 3
	padLength := tmp[:t+8]
	binary.BigEndian.PutUint64(padLength[t:], length)
	s.Write(padLength)

	if s.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [sha1Size]byte

	binary.BigEndian.PutUint32(digest[0:], s.h[0])
	binary.BigEndian.PutUint32(digest[4:], s.h[1])
	binary.BigEndian.PutUint32(digest[8:], s.h[2])
	binary.BigEndian.PutUint32(digest[12:], s.h[3])
	binary.BigEndian.PutUint32(digest[16:], s.h[4])

	return digest
}

func newKeyedSHA1(key, msg []byte) [sha1Size]byte {
	sha1 := newSHA1()
	sha1.Write(key)
	sha1.Write(msg)
	return sha1.digest()
}

func verifyKeyedSHA1(key, msg, expected []byte) bool {
	digest := newKeyedSHA1(key, msg)
	return bytes.Equal(digest[:], expected)
}

func padSHA1(msgLength int) []byte {
	length := uint64(msgLength)
	var tmp [64 + 8]byte
	tmp[0] = 0x80
	var t uint64
	if length%64 < 56 {
		t = 56 - length%64
	} else {
		t = 64 + 56 - length%64
	}

	length <<= 3
	padLength := tmp[:t+8]
	binary.BigEndian.PutUint64(padLength[t:], length)
	return padLength
}

func newKeyedSHA1CookieOracle() (
	cookie []byte,
	isAdmin func([]byte) bool,
) {
	key := make([]byte, 2+mathrand.IntN(100-1))
	rand.Read(key)

	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	digest := newKeyedSHA1(key, msg)

	cookie = append(cookie, digest[:]...)
	cookie = append(cookie, msg...)

	isAdmin = func(bs []byte) bool {
		mac, msg := bs[:sha1Size], bs[sha1Size:]
		if !verifyKeyedSHA1(key, msg, mac) {
			return false
		}
		return bytes.Contains(msg, []byte(";admin=true"))
	}
	return
}

func breakKeyedSHA1CookieOracle(cookie []byte, keySize int) []byte {
	mac, msg := cookie[:sha1Size], cookie[sha1Size:]

	padding := padSHA1(keySize + len(msg))
	attack := []byte(";admin=true")

	sha1 := newSHA1()
	sha1.h[0] = binary.BigEndian.Uint32(mac[0:])
	sha1.h[1] = binary.BigEndian.Uint32(mac[4:])
	sha1.h[2] = binary.BigEndian.Uint32(mac[8:])
	sha1.h[3] = binary.BigEndian.Uint32(mac[12:])
	sha1.h[4] = binary.BigEndian.Uint32(mac[16:])
	sha1.length = uint64(keySize + len(msg) + len(padding))
	sha1.Write(attack)

	adminCookie := append(append(msg, padding...), attack...)
	adminDigest := sha1.digest()
	return append(adminDigest[:], adminCookie...)
}

const (
	md4Size  = 16
	md4Chunk = 64

	md4Init0 = 0x67452301
	md4Init1 = 0xEFCDAB89
	md4Init2 = 0x98BADCFE
	md4Init3 = 0x10325476
)

type md4State struct {
	s      [md4Size / 4]uint32
	x      [md4Chunk]byte
	nx     int
	length uint64
}

func (m *md4State) reset() {
	m.s[0] = md4Init0
	m.s[1] = md4Init1
	m.s[2] = md4Init2
	m.s[3] = md4Init3
	m.nx = 0
	m.length = 0
}

func newMD4() *md4State {
	m := new(md4State)
	m.reset()
	return m
}

func (m *md4State) Write(p []byte) (nn int, err error) {
	nn = len(p)
	m.length += uint64(nn)
	if m.nx > 0 {
		n := min(len(p), md4Chunk-m.nx)
		for i := range n {
			m.x[m.nx+i] = p[i]
		}
		m.nx += n
		if m.nx == md4Chunk {
			m.block(m.x[0:])
			m.nx = 0
		}
		p = p[n:]
	}
	n := m.block(p)
	p = p[n:]
	if len(p) > 0 {
		m.nx = copy(m.x[:], p)
	}
	return
}

var (
	md4Shift1 = []int{3, 7, 11, 19}
	md4Shift2 = []int{3, 5, 9, 13}
	md4Shift3 = []int{3, 9, 11, 15}

	md4XIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	md4XIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
)

func (m *md4State) block(p []byte) int {
	a := m.s[0]
	b := m.s[1]
	c := m.s[2]
	d := m.s[3]
	n := 0
	var X [16]uint32
	for len(p) >= md4Chunk {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := range 16 {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// If this needs to be made faster in the future,
		// the usual trick is to unroll each of these
		// loops by a factor of 4; that lets you replace
		// the shift[] lookups with constants and,
		// with suitable variable renaming in each
		// unrolled body, delete the a, b, c, d = d, a, b, c
		// (or you can let the optimizer do the renaming).
		//
		// The index variables are uint so that % by a power
		// of two can be optimized easily by a compiler.

		// Round 1.
		for i := range uint(16) {
			x := i
			s := md4Shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		// Round 2.
		for i := range uint(16) {
			x := md4XIndex2[i]
			s := md4Shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		// Round 3.
		for i := range uint(16) {
			x := md4XIndex3[i]
			s := md4Shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[md4Chunk:]
		n += md4Chunk
	}

	m.s[0] = a
	m.s[1] = b
	m.s[2] = c
	m.s[3] = d
	return n
}

func (m *md4State) digest() [md4Size]byte {
	length := m.length
	var tmp [64]byte
	tmp[0] = 0x80
	if length%64 < 56 {
		m.Write(tmp[0 : 56-length%64])
	} else {
		m.Write(tmp[0 : 64+56-length%64])
	}

	// Length in bits.
	length <<= 3
	for i := range uint(8) {
		tmp[i] = byte(length >> (8 * i))
	}
	m.Write(tmp[0:8])

	if m.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [md4Size]byte

	binary.LittleEndian.PutUint32(digest[0:], m.s[0])
	binary.LittleEndian.PutUint32(digest[4:], m.s[1])
	binary.LittleEndian.PutUint32(digest[8:], m.s[2])
	binary.LittleEndian.PutUint32(digest[12:], m.s[3])

	return digest
}

func newKeyedMD4(key, msg []byte) [md4Size]byte {
	md4 := newMD4()
	md4.Write(key)
	md4.Write(msg)
	return md4.digest()
}

func verifyKeyedMD4(key, msg, expected []byte) bool {
	digest := newKeyedMD4(key, msg)
	return bytes.Equal(digest[:], expected)
}

func padMD4(msgLength int) []byte {
	length := uint64(msgLength)
	var tmp [64 + 8]byte
	tmp[0] = 0x80
	var t uint64
	if length%64 < 56 {
		t = 56 - length%64
	} else {
		t = 64 + 56 - length%64
	}

	length <<= 3
	padLength := tmp[:t+8]
	binary.LittleEndian.PutUint64(padLength[t:], length)
	return padLength
}

func newKeyedMD4CookieOracle() (
	cookie []byte,
	isAdmin func([]byte) bool,
) {
	key := make([]byte, 2+mathrand.IntN(100-1))
	rand.Read(key)

	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	digest := newKeyedMD4(key, msg)

	cookie = append(cookie, digest[:]...)
	cookie = append(cookie, msg...)

	isAdmin = func(bs []byte) bool {
		mac, msg := bs[:md4Size], bs[md4Size:]
		if !verifyKeyedMD4(key, msg, mac) {
			return false
		}
		return bytes.Contains(msg, []byte(";admin=true"))
	}
	return
}

func breakKeyedMD4CookieOracle(cookie []byte, keySize int) []byte {
	mac, msg := cookie[:md4Size], cookie[md4Size:]

	padding := padMD4(keySize + len(msg))
	attack := []byte(";admin=true")

	md4 := newMD4()
	md4.s[0] = binary.LittleEndian.Uint32(mac[0:])
	md4.s[1] = binary.LittleEndian.Uint32(mac[4:])
	md4.s[2] = binary.LittleEndian.Uint32(mac[8:])
	md4.s[3] = binary.LittleEndian.Uint32(mac[12:])
	md4.length = uint64(keySize + len(msg) + len(padding))
	md4.Write(attack)

	adminCookie := append(append(msg, padding...), attack...)
	adminDigest := md4.digest()
	return append(adminDigest[:], adminCookie...)
}

func newHMACSHA1Oracle(sleep time.Duration, keySize int) (
	sign func([]byte) []byte,
	verify func([]byte, []byte) bool,
) {
	key := make([]byte, 16)
	rand.Read(key)

	sign = func(file []byte) []byte {
		signature := hmacSHA1(key, file)
		return signature[:keySize]
	}
	verify = func(file, signature []byte) bool {
		expectedSig := hmacSHA1(key, []byte(file))
		return insecureCompare(signature, expectedSig[:keySize], sleep)
	}
	return
}

func hmacSHA1(key, msg []byte) [sha1Size]byte {
	const blockSize = 16
	blockKey := computeBlockKey(key, blockSize)

	opad := bytes.Repeat([]byte{0x5c}, blockSize)
	ipad := bytes.Repeat([]byte{0x36}, blockSize)

	sha1Outer := newSHA1()
	sha1Inner := newSHA1()

	sha1Inner.Write(fixedXOR(ipad, blockKey))
	sha1Inner.Write(msg)
	innerDigest := sha1Inner.digest()

	sha1Outer.Write(fixedXOR(opad, blockKey))
	sha1Outer.Write(innerDigest[:])
	return sha1Outer.digest()
}

func computeBlockKey(key []byte, blockSize int) []byte {
	switch {
	case len(key) > blockSize:
		sha1 := newSHA1()
		sha1.Write(key)
		blockKey := sha1.digest()
		return blockKey[:]
	case len(key) < blockSize:
		pad := make([]byte, blockSize-len(key))
		return append(pad, key...)
	default:
		return key
	}
}

func insecureCompare(a, b []byte, sleep time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(sleep)
	}
	return true
}

func timedVerify(file, sig []byte, verify func([]byte, []byte) bool) time.Duration {
	t0 := time.Now()
	verify(file, sig)
	return time.Since(t0)
}

func breakHMACSHA1Oracle(file []byte, verify func([]byte, []byte) bool, keySize int) []byte {
	sig := make([]byte, keySize)
	for i := range sig {
		baseline := timedVerify(file, sig, verify)
		found := false
		for b := range 256 {
			sig[i] = byte(b)
			duration := timedVerify(file, sig, verify)
			if duration-baseline > 25*time.Millisecond {
				found = true
				break
			}
		}
		if !found {
			sig[i] = 0x00
		}
	}
	return sig
}

func breakFasterHMACSHA1Oracle(file []byte, verify func([]byte, []byte) bool, keySize, attempts int) []byte {
	sig := make([]byte, keySize)
	for i := range sig {
		baseline := timedVerify(file, sig, verify)
		var stats [256]time.Duration
		for b := range stats {
			stats[b] = time.Duration(math.MaxInt64)
		}
		for range attempts {
			for b := range stats {
				sig[i] = byte(b)
				duration := timedVerify(file, sig, verify)
				stats[b] = min(stats[b], duration-baseline)
			}
		}
		maxStat := time.Duration(0)
		for b, s := range stats {
			if s > maxStat {
				maxStat = s
				sig[i] = byte(b)
			}
		}
	}
	return sig
}

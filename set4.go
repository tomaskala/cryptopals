package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"
	mathrand "math/rand/v2"
	"regexp"
	"strings"
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
	return fixedXor(p1, p3)
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
			block(s, s.x[:])
			s.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= sha1Chunk {
		n := len(p) &^ (sha1Chunk - 1)
		block(s, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		s.nx = copy(s.x[:], p)
	}
	return
}

func block(s *sha1State, p []byte) {
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

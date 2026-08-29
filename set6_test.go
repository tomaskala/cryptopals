package cryptopals

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestChallenge41(t *testing.T) {
	msg := []byte("hello, cryptopals!")
	pub, encrypt, decrypt := newRSAUnpaddedMessageRecoveryOracle(1024)

	capturedCiphertext := encrypt(msg)
	legitDecryption := decrypt(capturedCiphertext)
	if !bytes.Equal(legitDecryption, msg) {
		t.Fatalf("legit decryption error: expected %v, got %v", msg, legitDecryption)
	}

	if decrypt(capturedCiphertext) != nil {
		t.Fatalf("repeated decryption should not be possible")
	}

	decrypted := breakRSAUnpaddedMessageRecoveryOracle(capturedCiphertext, pub, decrypt)
	if !bytes.Equal(decrypted, msg) {
		t.Errorf("expected %v, got %v", msg, decrypted)
	}
}

func TestChallenge42(t *testing.T) {
	msg := []byte("hi mom")
	keySizeBits := 2048
	verify := newRSASignatureOracle(keySizeBits)
	sig := forgeRSASignature(msg, keySizeBits)
	if !verify(msg, sig) {
		t.Error("signature not valid")
	}
}

func TestChallenge43(t *testing.T) {
	t.Run("DSA implementation correctness", func(t *testing.T) {
		msg := []byte("hello, cryptopals!")
		x, y := cryptopalsDSAParams.generate()
		r, s := cryptopalsDSAParams.sign(x, msg)
		if !cryptopalsDSAParams.verify(y, r, s, msg) {
			t.Fatalf("verification failed")
		}
	})

	t.Run("DSA key recovery from small nonce", func(t *testing.T) {
		y := hexToBig(t, "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17")
		msg := []byte(`For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
`)
		msgDigest := sha1.Sum(msg)
		expectedMsgDigest := hexDecode(t, "d2d0714f014a9784047eaeccf956520045c45265")
		if !bytes.Equal(msgDigest[:], expectedMsgDigest) {
			t.Fatalf("expected msg digest %v, got %v", expectedMsgDigest, msgDigest)
		}

		r := decToBig(t, "548099063082341131477253921760299949438196259240")
		s := decToBig(t, "857042759984254168557880549501802188789837994940")

		privateKey := recoverDSAPrivateKeyFromSmallNonce(cryptopalsDSAParams, y, r, s, msg)

		privateKeyDigest := sha1.Sum([]byte(hex.EncodeToString(privateKey.Bytes())))
		expectedPrivateKeyDigest := hexDecode(t, "0954edd5e0afe5542a4adf012611a91912a3ec16")
		if !bytes.Equal(privateKeyDigest[:], expectedPrivateKeyDigest) {
			t.Errorf("expected private key digest %v, got %v", expectedPrivateKeyDigest, privateKeyDigest)
		}
	})
}

func decToBig(t *testing.T, s string) *big.Int {
	t.Helper()
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("error converting decimal to big integer from %s", s)
	}
	return b
}

func hexToBig(t *testing.T, s string) *big.Int {
	t.Helper()
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("error converting hex to big integer from %s", s)
	}
	return b
}

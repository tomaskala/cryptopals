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

		x := recoverDSAPrivateKeyFromSmallNonce(cryptopalsDSAParams, y, r, s, msg)

		privateKeyDigest := sha1.Sum([]byte(hex.EncodeToString(x.Bytes())))
		expectedPrivateKeyDigest := hexDecode(t, "0954edd5e0afe5542a4adf012611a91912a3ec16")
		if !bytes.Equal(privateKeyDigest[:], expectedPrivateKeyDigest) {
			t.Errorf("expected private key digest %v, got %v", expectedPrivateKeyDigest, privateKeyDigest)
		}
	})
}

func TestChallenge44(t *testing.T) {
	msg1 := []byte("Listen for me, you better listen for me now. ")
	s1 := decToBig(t, "1267396447369736888040262262183731677867615804316")

	msg2 := []byte("Pure black people mon is all I mon know. ")
	s2 := decToBig(t, "1021643638653719618255840562522049391608552714967")

	r := decToBig(t, "1105520928110492191417703162650245113664610474875")
	y := hexToBig(t, "2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821")

	x := recoverDSAPrivateKeyFromRepeatedNonce(cryptopalsDSAParams, r, s1, s2, msg1, msg2)
	privateKeyDigest := sha1.Sum([]byte(hex.EncodeToString(x.Bytes())))
	expectedPrivateKeyDigest := hexDecode(t, "ca8f6f7c66fa362d40760d135b763eb8527d3d52")
	if !bytes.Equal(privateKeyDigest[:], expectedPrivateKeyDigest) {
		t.Errorf("expected private key digest %v, got %v", expectedPrivateKeyDigest, privateKeyDigest)
	}

	r12, s12 := cryptopalsDSAParams.sign(x, msg1)
	if !cryptopalsDSAParams.verify(y, r12, s12, msg1) {
		t.Errorf("msg1 verification failed")
	}
	r22, s22 := cryptopalsDSAParams.sign(x, msg2)
	if !cryptopalsDSAParams.verify(y, r22, s22, msg2) {
		t.Errorf("msg2 verification failed")
	}
}

func TestChallenge45(t *testing.T) {
	_, y := cryptopalsDSAParams.generate()

	hijackedDSAParams := dsaParameters{
		p: cryptopalsDSAParams.p,
		q: cryptopalsDSAParams.q,
		g: new(big.Int).Add(cryptopalsDSAParams.p, big.NewInt(1)),
	}
	r, s := magicDSASignatureForG1(cryptopalsDSAParams.p, cryptopalsDSAParams.q, y)

	msg1 := []byte("Hello, world")
	if !hijackedDSAParams.verify(y, r, s, msg1) {
		t.Errorf("msg1 verification failed")
	}

	msg2 := []byte("Goodbye, world")
	if !hijackedDSAParams.verify(y, r, s, msg2) {
		t.Errorf("msg2 verification failed")
	}
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

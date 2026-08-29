package cryptopals

import (
	"bytes"
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

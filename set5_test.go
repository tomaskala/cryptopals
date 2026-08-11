package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestChallenge33(t *testing.T) {
	g := big.NewInt(3)
	dh := dhParams{g: g, p: p}

	alicePrivate := dh.genPrivate()
	alicePublic := dh.genPublic(alicePrivate)

	bobPrivate := dh.genPrivate()
	bobPublic := dh.genPublic(bobPrivate)

	aliceSecret := dh.genSecret(alicePrivate, bobPublic)
	bobSecret := dh.genSecret(bobPrivate, alicePublic)

	if aliceSecret.Cmp(bobSecret) != 0 {
		t.Errorf("alice's secret %v is different from bob's secret %v", aliceSecret, bobSecret)
	}
}

func TestChallenge34(t *testing.T) {
	t.Run("DH protocol", func(t *testing.T) {
		g := big.NewInt(3)
		dh := dhParams{g: g, p: p}
		alice, bob := createEchoBot(dh)
		msg := []byte("hello, cryptopals!")

		aliceToBob := alice.encrypt(msg)
		bobDecrypted := bob.decrypt(aliceToBob)
		if !bytes.Equal(bobDecrypted, msg) {
			t.Errorf("expected bob to decrypt %v, got %v", msg, bobDecrypted)
		}

		bobToAlice := bob.encrypt(bobDecrypted)
		aliceDecrypted := alice.decrypt(bobToAlice)
		if !bytes.Equal(aliceDecrypted, msg) {
			t.Errorf("expected alice to decrypt %v, got %v", msg, aliceDecrypted)
		}
	})

	t.Run("DH protocol with MITM", func(t *testing.T) {
		g := big.NewInt(3)
		dh := dhParams{g: g, p: p}
		alice, eve, bob := createMITMEchoBot(dh)
		msg := []byte("hello, cryptopals!")

		aliceToBob := alice.encrypt(msg)
		eveDecryptedToBob := eve.decrypt(aliceToBob)
		if !bytes.Equal(eveDecryptedToBob, msg) {
			t.Errorf("expected eve to decrypt %v, got %v", msg, eveDecryptedToBob)
		}
		bobDecrypted := bob.decrypt(aliceToBob)
		if !bytes.Equal(bobDecrypted, msg) {
			t.Errorf("expected bob to decrypt %v, got %v", msg, bobDecrypted)
		}

		bobToAlice := bob.encrypt(bobDecrypted)
		eveDecryptedToAlice := eve.decrypt(bobToAlice)
		if !bytes.Equal(eveDecryptedToAlice, msg) {
			t.Errorf("expected eve to decrypt %v, got %v", msg, eveDecryptedToAlice)
		}
		aliceDecrypted := alice.decrypt(bobToAlice)
		if !bytes.Equal(aliceDecrypted, msg) {
			t.Errorf("expected alice to decrypt %v, got %v", msg, aliceDecrypted)
		}
	})
}

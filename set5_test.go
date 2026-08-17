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

func TestChallenge35(t *testing.T) {
	t.Run("g = 1", func(t *testing.T) {
		g := big.NewInt(3)
		dh := dhParams{g: g, p: p}
		alice, eve, bob := createMITMEchoBotG1(dh)
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

	t.Run("g = p", func(t *testing.T) {
		g := big.NewInt(3)
		dh := dhParams{g: g, p: p}
		alice, eve, bob := createMITMEchoBotGp(dh)
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

	t.Run("g = p-1", func(t *testing.T) {
		g := big.NewInt(3)
		dh := dhParams{g: g, p: p}
		alice, eve, bob := createMITMEchoBotGpm1(dh)
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

func TestChallenge36(t *testing.T) {
	g := big.NewInt(2)
	dh := dhParams{g: g, p: p}
	email := "test@example.com"
	password := []byte("secret password")

	server := newRealSRPServer(dh)
	client := newRealSRPClient(dh, email, password)
	server.register(email, deriveCredentials(dh, password))

	if !client.login(server) {
		t.Errorf("client did not login successfully")
	}
}

func TestChallenge37(t *testing.T) {
	g := big.NewInt(2)
	dh := dhParams{g: g, p: p}
	email := "test@example.com"
	password := []byte("secret password")

	server := newRealSRPServer(dh)
	server.register(email, deriveCredentials(dh, password))

	if !bypassLogin(email, server) {
		t.Errorf("client did not bypass the login successfully")
	}
}

func TestChallenge38(t *testing.T) {
	g := big.NewInt(2)
	dh := dhParams{g: g, p: p}
	email := "test@example.com"
	password := []byte("secret password")

	t.Run("simplified server", func(t *testing.T) {
		server := newSimplifiedSRPServer(dh)
		client := newSimplifiedSRPClient(dh, email, password)
		server.register(email, deriveCredentials(dh, password))

		if !client.login(server) {
			t.Errorf("client did not login successfully to a simplified server")
		}
	})

	t.Run("MITM server", func(t *testing.T) {
		server := newMITMSRPServer(dh)
		client := newSimplifiedSRPClient(dh, email, password)
		server.register(email, deriveCredentials(dh, password))

		if !client.login(server) {
			t.Errorf("client did not login successfully to a MITM server")
		}
		if server.tryPassword([]byte("incorrect password")) {
			t.Errorf("MITM server cracked a wrong password")
		}
		if !server.tryPassword(password) {
			t.Errorf("MITM server did not crack the correct password")
		}
	})
}

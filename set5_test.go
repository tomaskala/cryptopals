package cryptopals

import (
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

package cryptopals

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func TestChallenge49(t *testing.T) {
	attackerID := "1337"
	victimID := "6969"
	amount := 1000000

	t.Run("part 1 sanity check", func(t *testing.T) {
		client, server := newCBCMACOracle(attackerID)

		tx := client(victimID, amount)
		v, err := server(tx)
		if err != nil {
			t.Fatalf("error validating benign transaction: %v", err)
		}

		if got := v.Get("from"); got != attackerID {
			t.Errorf("expected from %s, got %s", attackerID, got)
		}

		if got := v.Get("to"); got != victimID {
			t.Errorf("expected to %s, got %s", victimID, got)
		}

		if got := v.Get("amount"); got != strconv.Itoa(amount) {
			t.Errorf("expected amount %d, got %s", amount, got)
		}

		tx[0] += 1
		_, err = server(tx)
		if err == nil {
			t.Errorf("tampered transaction validated successfully")
		}
	})

	t.Run("tamper message with client-chosen IV", func(t *testing.T) {
		client, server := newCBCMACOracle(attackerID)
		tx := breakCBCMACOracle(attackerID, victimID, amount, client)
		v, err := server(tx)

		if err != nil {
			t.Fatalf("error validating tampered transaction: %v", err)
		}

		if got := v.Get("from"); got != victimID {
			t.Errorf("expected from %s, got %s", victimID, got)
		}

		if got := v.Get("to"); got != attackerID {
			t.Errorf("expected to %s, got %s", attackerID, got)
		}

		if got := v.Get("amount"); got != strconv.Itoa(amount) {
			t.Errorf("expected amount %d, got %s", amount, got)
		}
	})

	t.Run("part 2 transaction sanity check", func(t *testing.T) {
		tx1 := transaction{
			senderID: "sender",
			recipients: []recipient{
				{recipientID: "recipient1", amount: 1234},
				{recipientID: "recipient2", amount: 13376969},
				{recipientID: "recipient3", amount: 1000000},
			},
		}

		buf1 := tx1.encode()
		var tx2 transaction
		if err := tx2.decode(buf1); err != nil {
			t.Fatalf("error decoding transaction: %v", err)
		}

		if !transactionsEqual(t, tx1, tx2) {
			t.Fatalf("tx1 (%v) differs from tx2 (%v)", tx1, tx2)
		}

		buf2 := tx2.encode()
		if !bytes.Equal(buf1, buf2) {
			t.Errorf("tx1 serialized to %s but tx2 serialized to %s", buf1, buf2)
		}
	})

	t.Run("part 2 API sanity check", func(t *testing.T) {
		_, client, server := newCBCMACRepeatedOracle(attackerID, transaction{})
		recipients := []recipient{
			{recipientID: "recipient1", amount: 1234},
			{recipientID: "recipient2", amount: 13376969},
			{recipientID: "recipient3", amount: 1000000},
		}
		msg := client(recipients)
		tx2, err := server(msg)
		if err != nil {
			t.Fatalf("error validating transaction: %v", err)
		}
		tx1 := transaction{senderID: attackerID, recipients: recipients}
		if !transactionsEqual(t, tx1, tx2) {
			t.Errorf("tx1 (%v) differs from tx2 (%v)", tx1, tx2)
		}

		msg[0] += 1
		_, err = server(msg)
		if err == nil {
			t.Errorf("tampered transaction validated successfully")
		}
	})

	t.Run("length extension attack", func(t *testing.T) {
		capturedTx := transaction{
			senderID: victimID,
			recipients: []recipient{
				{recipientID: "rec1", amount: 9999},
				{recipientID: "rec2", amount: 8888},
			},
		}

		capturedMsg, client, server := newCBCMACRepeatedOracle(attackerID, capturedTx)
		tamperedMsg := breakCBCMACRepeatedOracle(capturedMsg, attackerID, client)

		tx, err := server(tamperedMsg)
		if err != nil {
			if strings.Contains(err.Error(), "invalid semicolon separator in query") {
				t.Skipf("skipping flaky test, because glue happened to corrupt URL values: %v", err)
			} else {
				t.Errorf("error validating tampered transaction: %v", err)
			}
		}

		found := false
		foundAmount := 0
		for _, r := range tx.recipients {
			if r.recipientID == attackerID {
				found = true
				foundAmount = r.amount
				break
			}
		}

		if !found {
			t.Errorf("attackerID not found among recipients")
		}
		if foundAmount != amount {
			t.Errorf("expected amount %d, got %d", amount, foundAmount)
		}
	})
}

func transactionsEqual(t *testing.T, tx1, tx2 transaction) bool {
	t.Helper()

	if tx1.senderID != tx2.senderID {
		return false
	}

	if len(tx1.recipients) != len(tx2.recipients) {
		return false
	}

	for i := range tx1.recipients {
		recipient1 := tx1.recipients[i]
		recipient2 := tx2.recipients[i]

		if recipient1.recipientID != recipient2.recipientID {
			return false
		}
		if recipient1.amount != recipient2.amount {
			return false
		}
	}

	return true
}

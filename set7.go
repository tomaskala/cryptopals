package cryptopals

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	mathrand "math/rand/v2"
	"net/url"
	"strconv"
	"strings"
)

func createCBCMAC(iv, msg []byte, block cipher.Block) []byte {
	p := padPKCS7(msg, aesBlockSize)
	c := encryptCBC(iv, p, block)
	return c[len(c)-aesBlockSize:]
}

func checkCBCMAC(iv, msg []byte, block cipher.Block, mac []byte) bool {
	expected := createCBCMAC(iv, msg, block)
	return hmac.Equal(mac, expected)
}

func newCBCMACOracle(senderID string) (
	client func(string, int) []byte,
	server func([]byte) (url.Values, error),
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	client = func(recipientID string, amount int) []byte {
		// We cannot use url.Values.Encode here, because it sorts alphabetically by key
		// and the attack assumes that the "from=<senderID>" key-value appears first.
		var buf bytes.Buffer
		buf.WriteString("from=")
		buf.WriteString(senderID)
		buf.WriteByte('&')
		buf.WriteString("to=")
		buf.WriteString(recipientID)
		buf.WriteByte('&')
		buf.WriteString("amount=")
		buf.WriteString(strconv.Itoa(amount))
		msg := buf.Bytes()

		iv := make([]byte, aesBlockSize)
		rand.Read(iv)

		mac := createCBCMAC(iv, msg, block)

		var tx []byte
		tx = append(tx, msg...)
		tx = append(tx, iv...)
		tx = append(tx, mac...)
		return tx
	}
	server = func(tx []byte) (url.Values, error) {
		if len(tx) < 2*aesBlockSize {
			return nil, errors.New("message too short")
		}
		msg := tx[:len(tx)-2*aesBlockSize]
		iv := tx[len(tx)-2*aesBlockSize : len(tx)-aesBlockSize]
		mac := tx[len(tx)-aesBlockSize:]

		if !checkCBCMAC(iv, msg, block, mac) {
			return nil, errors.New("invalid MAC")
		}

		v, err := url.ParseQuery(string(msg))
		if err != nil {
			return nil, err
		}

		return v, nil
	}
	return
}

func breakCBCMACOracle(attackerID, victimID string, amount int, client func(string, int) []byte) []byte {
	const prefixLen = 4 + 1 // len("from=")

	if len(attackerID) != len(victimID) {
		panic("attacker and victim ID lenghts differ")
	}
	if len(attackerID) > aesBlockSize-prefixLen {
		panic("ID too long")
	}

	// msg || iv || mac
	tx := client(attackerID, amount)

	// from=<attackerID>&to=<attackerID>&amount=<amount>
	msg := tx[:len(tx)-2*aesBlockSize]
	iv := tx[len(tx)-2*aesBlockSize : len(tx)-aesBlockSize]
	mac := tx[len(tx)-aesBlockSize:]

	prefix := msg[:prefixLen]
	suffix := msg[prefixLen+len(attackerID):]

	for i := range attackerID {
		// real E1 = AES(victim ^ abcdef)
		// fake E1 = AES(attack ^ abcdef ^ attack ^ victim)
		iv[prefixLen+i] ^= attackerID[i] ^ victimID[i]
	}

	var buf []byte
	// from=<victimID>&to=<attackerID>&amount=<amount>
	buf = append(buf, prefix...)
	buf = append(buf, []byte(victimID)...)
	buf = append(buf, suffix...)
	buf = append(buf, iv...)
	buf = append(buf, mac...)
	return buf
}

type recipient struct {
	recipientID string
	amount      int
}

type transaction struct {
	senderID   string
	recipients []recipient
}

func (t *transaction) encode() []byte {
	var buf bytes.Buffer
	for i, r := range t.recipients {
		if i > 0 {
			buf.WriteByte(';')
		}
		buf.WriteString(r.recipientID)
		buf.WriteByte(':')
		buf.WriteString(strconv.Itoa(r.amount))
	}

	v := url.Values{}
	v.Set("from", t.senderID)
	v.Set("tx_list", buf.String())
	return []byte(v.Encode())
}

func (t *transaction) decode(buf []byte) error {
	v, err := url.ParseQuery(string(buf))
	if err != nil {
		return fmt.Errorf("error parsing query: %w", err)
	}
	if !v.Has("from") {
		return errors.New("error decoding sender ID")
	}
	if !v.Has("tx_list") {
		return errors.New("error decoding tx_list")
	}
	t.senderID = v.Get("from")
	recipients := strings.SplitSeq(v.Get("tx_list"), ";")
	for r := range recipients {
		parts := strings.Split(r, ":")
		if len(parts) != 2 {
			continue
		}
		amount, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		t.recipients = append(t.recipients, recipient{recipientID: parts[0], amount: amount})
	}
	return nil
}

func newCBCMACRepeatedOracle(senderID string, capturedTx transaction) (
	capturedMsg []byte,
	client func(recipients []recipient) []byte,
	server func([]byte) (transaction, error),
) {
	key := make([]byte, aesBlockSize)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, aesBlockSize)

	capturedTxBytes := capturedTx.encode()

	capturedMsg = append(capturedTxBytes, createCBCMAC(iv, capturedTxBytes, block)...)
	client = func(recipients []recipient) []byte {
		tx := transaction{
			senderID:   senderID,
			recipients: recipients,
		}
		msg := tx.encode()
		mac := createCBCMAC(iv, msg, block)

		var buf []byte
		buf = append(buf, msg...)
		buf = append(buf, mac...)
		return buf
	}
	server = func(buf []byte) (transaction, error) {
		var tx transaction
		if len(buf) < aesBlockSize {
			return tx, errors.New("message too short")
		}

		msg := buf[:len(buf)-aesBlockSize]
		mac := buf[len(buf)-aesBlockSize:]
		if !checkCBCMAC(iv, msg, block, mac) {
			return tx, errors.New("invalid MAC")
		}
		if err := tx.decode(msg); err != nil {
			return tx, fmt.Errorf("error decoding transaction: %w", err)
		}
		return tx, nil
	}
	return
}

func breakCBCMACRepeatedOracle(captured []byte, attackerID string, client func([]recipient) []byte) []byte {
	if len(attackerID) != 4 {
		panic("the padding used in the attack assumes 4-byte IDs")
	}

	msg := captured[:len(captured)-aesBlockSize]
	mac := captured[len(captured)-aesBlockSize:]

	extension := client([]recipient{
		{recipientID: attackerID, amount: 1},
		{recipientID: attackerID, amount: 1000000},
	})
	glue := fixedXOR(extension[:aesBlockSize], mac)

	var tamperedMsg []byte
	tamperedMsg = append(tamperedMsg, padPKCS7(msg, aesBlockSize)...)
	tamperedMsg = append(tamperedMsg, glue...)
	tamperedMsg = append(tamperedMsg, extension[aesBlockSize:]...)
	return tamperedMsg
}

func forgeCBCMACJSSnippet(iv, msg, mac []byte, block cipher.Block) []byte {
	var msgWithComment []byte
	msgWithComment = append(msgWithComment, msg...)
	msgWithComment = append(msgWithComment, []byte("/*")...)
	c := createCBCMAC(iv, msgWithComment, block)

	p4 := []byte("**************/") // One less bytes than aesBlockSize.
	buf := make([]byte, aesBlockSize)

	block.Decrypt(buf, mac)
	p3 := fixedXOR(padPKCS7(p4, aesBlockSize), buf)
	block.Decrypt(buf, p3)
	p3 = fixedXOR(c, buf)

	var res []byte
	res = append(res, padPKCS7(msgWithComment, aesBlockSize)...)
	res = append(res, p3...)
	res = append(res, p4...)
	return res
}

func newCompressionOracle(cookie []byte) (
	streamCipherOracle func([]byte) []byte,
	blockCipherOracle func([]byte) []byte,
) {
	header := `POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=%s
Content-Length: %d

%s
`
	preparePlaintext := func(payload []byte) []byte {
		request := fmt.Sprintf(header, cookie, len(payload), payload)

		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		w.Write([]byte(request))
		w.Close()

		return buf.Bytes()
	}

	streamCipherOracle = func(payload []byte) []byte {
		plaintext := preparePlaintext(payload)

		key := make([]byte, aesBlockSize)
		rand.Read(key)

		iv := make([]byte, aesBlockSize)
		rand.Read(iv)

		ciphertext := make([]byte, aesBlockSize+len(plaintext))
		copy(ciphertext, iv)

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ctr := cipher.NewCTR(block, iv)
		ctr.XORKeyStream(ciphertext[aesBlockSize:], plaintext)

		return ciphertext
	}
	blockCipherOracle = func(payload []byte) []byte {
		plaintext := preparePlaintext(payload)

		key := make([]byte, aesBlockSize)
		rand.Read(key)

		iv := make([]byte, aesBlockSize)
		rand.Read(iv)

		ciphertext := make([]byte, aesBlockSize+len(padPKCS7(plaintext, aesBlockSize)))
		copy(ciphertext, iv)

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(ciphertext[aesBlockSize:], padPKCS7(plaintext, aesBlockSize))

		return ciphertext
	}
	return
}

func breakStreamCipherCompressionOracle(oracle func([]byte) []byte) []byte {
	const anchor = "Cookie: sessionid="
	cookie := []byte(anchor)

	for cookie[len(cookie)-1] != '\n' {
		cookie = append(cookie, '*')
		var argMin byte
		minLength := math.MaxInt

		for b := range 256 {
			cookie[len(cookie)-1] = byte(b)
			request := oracle(cookie)

			if len(request) < minLength {
				argMin = byte(b)
				minLength = len(request)
			}
		}

		cookie[len(cookie)-1] = argMin
	}

	return cookie[len(anchor) : len(cookie)-1]
}

func breakBlockCipherCompressionOracle(oracle func([]byte) []byte) []byte {
	const anchor = "Cookie: sessionid="
	cookie := []byte(anchor)

	for cookie[len(cookie)-1] != '\n' {
		cookie = append(cookie, '*')
		var padding []byte

		for {
			var argMin byte
			minLength1, minLength2 := math.MaxInt, math.MaxInt

			for b := range 256 {
				cookie[len(cookie)-1] = byte(b)
				buf := append([]byte{}, padding...)
				buf = append(buf, cookie...)
				request := oracle(buf)

				if len(request) < minLength1 {
					minLength2 = minLength1
					minLength1 = len(request)
					argMin = byte(b)
				} else if len(request) < minLength2 {
					minLength2 = len(request)
				}
			}

			if minLength1 < minLength2 {
				cookie[len(cookie)-1] = argMin
				break
			}
			padding = append(padding, byte(mathrand.N(256)))
		}
	}

	return cookie[len(anchor) : len(cookie)-1]
}

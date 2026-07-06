package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestChallenge01(t *testing.T) {
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	converted := hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

	if converted != expected {
		t.Errorf("expected: %s, got: %s", expected, converted)
	}
}

func TestChallenge02(t *testing.T) {
	bs1 := hexDecode(t, "1c0111001f010100061a024b53535009181c")
	bs2 := hexDecode(t, "686974207468652062756c6c277320657965")
	expected := hexDecode(t, "746865206b696420646f6e277420706c6179")
	xor := fixedXor(bs1, bs2)

	if !bytes.Equal(xor, expected) {
		t.Errorf("expected: %v, got: %v", expected, xor)
	}
}

func TestChallenge03(t *testing.T) {
	text := readFile(t, "resources/alices-adventures-in-wonderland.txt")
	freq := byteFrequency(text)

	bs := hexDecode(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	key, plaintext, score := detectSingleByteXOR(bs, freq)
	t.Logf("key: %c, plaintext: %s, score: %f", key, plaintext, score)
}

func TestChallenge04(t *testing.T) {
	text := readFile(t, "resources/alices-adventures-in-wonderland.txt")
	freq := byteFrequency(text)

	ciphertexts := readFile(t, "resources/challenge04.txt")
	var bestKey byte
	var bestPlaintext []byte
	var bestScore float64

	for line := range strings.Lines(string(ciphertexts)) {
		bs := []byte(hexDecode(t, strings.TrimSpace(line)))
		key, plaintext, score := detectSingleByteXOR(bs, freq)

		if score > bestScore {
			bestKey = key
			bestPlaintext = plaintext
			bestScore = score
		}
	}

	t.Logf("key: %c, plaintext: %s, score: %f", bestKey, bestPlaintext, bestScore)
}

func TestChallenge05(t *testing.T) {
	plaintext := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	key := []byte("ICE")

	expected := hexDecode(t, `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`)
	ciphertext := repeatingKeyXOR(plaintext, key)

	if !bytes.Equal(ciphertext, expected) {
		t.Errorf("expected: %v, got: %v", expected, ciphertext)
	}
}

func TestChallenge06(t *testing.T) {
	if dist := hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")); dist != 37 {
		t.Fatalf("expected Hamming distance 37, got %d", dist)
	}

	text := readFile(t, "resources/alices-adventures-in-wonderland.txt")
	freq := byteFrequency(text)

	ciphertext := base64Decode(t, string(readFile(t, "resources/challenge06.txt")))

	keySize := findRepeatingKeySize(ciphertext)
	t.Logf("detected key size: %d", keySize)

	key := findRepeatingKey(ciphertext, keySize, freq)
	t.Logf("detected key: %s", key)

	plaintext := repeatingKeyXOR(ciphertext, key)
	t.Logf("plaintext: %s", plaintext)
}

func TestChallenge07(t *testing.T) {
	ciphertext := base64Decode(t, string(readFile(t, "resources/challenge07.txt")))
	key := []byte("YELLOW SUBMARINE")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := decryptECB(ciphertext, block)
	t.Logf("plaintext: %s", plaintext)

	reencrypted := encryptECB(plaintext, block)
	if !bytes.Equal(ciphertext, reencrypted) {
		t.Errorf("expected: %v, got: %v", ciphertext, reencrypted)
	}

	redecrypted := decryptECB(reencrypted, block)
	if !bytes.Equal(plaintext, redecrypted) {
		t.Errorf("expected: %v, got: %v", plaintext, redecrypted)
	}
}

func TestChallenge08(t *testing.T) {
	ciphertexts := readFile(t, "resources/challenge08.txt")

	i := 0
	for line := range strings.Lines(string(ciphertexts)) {
		bs := []byte(hexDecode(t, strings.TrimSpace(line)))
		if detectECB(bs, 16) {
			t.Logf("detected ECB on line %d: %v", i+1, bs)
		}
		i++
	}
}

func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func base64Decode(t *testing.T, s string) []byte {
	t.Helper()
	res, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

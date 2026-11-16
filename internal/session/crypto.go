package session

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"

	"github.com/geeksbaek/seed"
)

// encryptLogin implements the KAIST login form's SEED128-CBC/ANSI X9.23
// transform. Although the page parses a 32-byte key, its SEED implementation
// consumes only the first 16 bytes; the IV starts at hex character 64.
// HTTPS still authenticates the endpoint and protects the entire exchange.
func encryptLogin(loginKey string, plaintext []byte) (string, error) {
	if len(loginKey) < 96 || len(loginKey) > 4096 {
		return "", errors.New("invalid login encryption parameters")
	}
	material, err := hex.DecodeString(loginKey[:96])
	if err != nil {
		return "", errors.New("invalid login encryption parameters")
	}
	defer clear(material)
	block, err := seed.NewCipher(material[:16])
	if err != nil {
		return "", errors.New("could not initialize login encryption")
	}
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := make([]byte, len(plaintext)+padding)
	defer clear(padded)
	copy(padded, plaintext)
	padded[len(padded)-1] = byte(padding)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, material[32:48]).CryptBlocks(out, padded)
	return hex.EncodeToString(out), nil
}

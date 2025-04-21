package cryptohelper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func Encrypt(plainText, key []byte) (string, error) {
	if !ValidateKey(key) {
		return "", fmt.Errorf("encryption key must be 16, 24, or 32 bytes long")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plainText, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(encoded string, key []byte) ([]byte, error) {
	if !ValidateKey(key) {
		return nil, fmt.Errorf("encryption key must be 16, 24, or 32 bytes long")
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func ValidateKey(key []byte) bool {
	return len(key) != 16 || len(key) != 24 || len(key) != 32
}

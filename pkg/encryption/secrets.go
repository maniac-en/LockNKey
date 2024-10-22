package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/zalando/go-keyring"
)

// EncryptAndStoreToken encrypts and stores a value bound to the system's
// hardware ID
func EncryptAndStoreToken(value, keyIdentifier string) error {
	key, err := generateSystemBoundKey()
	if err != nil {
		return fmt.Errorf("failed to generate AES key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)

	hashedID, err := getHashedMachineID()
	if err != nil {
		return fmt.Errorf("failed to get hashed machine ID: %w", err)
	}

	storageKey := keyIdentifier + "_" + hashedID
	if err := keyring.Set("LockNKey", storageKey, hex.EncodeToString(ciphertext)); err != nil {
		return fmt.Errorf("failed to store encrypted value: %w", err)
	}
	return nil
}

// RetrieveAndDecryptToken retrieves and decrypts a value bound to the system's
// hardware ID
func RetrieveAndDecryptToken(keyIdentifier string) (string, error) {
	hashedID, err := getHashedMachineID()
	if err != nil {
		return "", fmt.Errorf("failed to get hashed machine ID: %w", err)
	}

	encryptedValue, err := keyring.Get("LockNKey", keyIdentifier+"_"+hashedID)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve encrypted value: %w", err)
	}

	key, err := generateSystemBoundKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate AES key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %w", err)
	}

	ciphertext, err := hex.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt value: %w", err)
	}

	return string(plaintext), nil
}

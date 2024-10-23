package authentication

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/maniac-en/locknkey/pkg/encryption"
	"github.com/maniac-en/locknkey/pkg/utils"
	"github.com/zalando/go-keyring"
)

// GenerateAndStoreKeys generates a system-bound RSA key pair and stores the private key securely
func GenerateAndStoreKeys() (*rsa.PrivateKey, []byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Generating RSA key pair")

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Error("Failed to generate RSA key", "error", err)
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	hashedID, err := utils.GetHashedMachineID()
	if err != nil {
		logger.Error("Failed to retrieve machine ID", "error", err)
		return nil, nil, fmt.Errorf("failed to retrieve machine ID: %w", err)
	}
	logger.Debug("Machine ID retrieved", "hashedID", hashedID)

	err = keyring.Set("LockNKey", "privateKey_"+hashedID, string(privateKeyPEM))
	if err != nil {
		logger.Error("Failed to store private key", "error", err)
		return nil, nil, fmt.Errorf("failed to store private key: %w", err)
	}
	logger.Info("Private key stored securely.")

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})
	err = keyring.Set("LockNKey", "publicKey_"+hashedID, string(publicKeyPEM))
	if err != nil {
		logger.Error("Failed to store public key", "error", err)
		return nil, nil, fmt.Errorf("failed to store public key: %w", err)
	}
	logger.Info("Public key stored securely.")

	return privateKey, publicKeyPEM, nil
}

// RetrievePrivateKey retrieves the private key for the current user
func RetrievePrivateKey() ([]byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Retrieving user's Private Key")

	hashedID, err := utils.GetHashedMachineID()
	if err != nil {
		logger.Error("Failed to retrieve machine ID", "error", err)
		return nil, fmt.Errorf("failed to retrieve machine ID: %w", err)
	}
	logger.Debug("Machine ID retrieved", "hashedID", hashedID)

	privateKeyPEM, err := keyring.Get("LockNKey", "privateKey_"+hashedID)
	if err != nil {
		logger.Error("Failed to retrieve private key", "error", err)
		return nil, fmt.Errorf("failed to retrieve private key: %w", err)
	}
	logger.Info("Private key retrieved securely.")

	privateKeyBytes := []byte(privateKeyPEM)
	return privateKeyBytes, nil
}

// RetrievePublicKey retrieves the public key for the current user
func RetrievePublicKey() ([]byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Retrieving user's Public Key")

	hashedID, err := utils.GetHashedMachineID()
	if err != nil {
		logger.Error("Failed to retrieve machine ID", "error", err)
		return nil, fmt.Errorf("failed to retrieve machine ID: %w", err)
	}
	logger.Debug("Machine ID retrieved", "hashedID", hashedID)

	publicKeyPEM, err := keyring.Get("LockNKey", "publicKey_"+hashedID)
	if err != nil {
		logger.Error("Failed to retrieve public key", "error", err)
		return nil, fmt.Errorf("failed to retrieve public key: %w", err)
	}
	logger.Info("Public key retrieved securely.")

	publicKeyBytes := []byte(publicKeyPEM)
	return publicKeyBytes, nil
}

func ComparePublicKey(publicKey []byte) (bool, error) {
	logger := utils.GetLogger()
	logger.Debug("Comparing provided public key with stored public key")

	// Retrieve the user's public key from storage
	storedPublicKey, err := RetrievePublicKey()
	if err != nil {
		logger.Error("Failed to retrieve stored public key", "error", err)
		return false, fmt.Errorf("failed to retrieve stored public key: %w", err)
	}

	// Calculate the hash of the stored public key
	storedKeyHash := sha256.Sum256(storedPublicKey)
	logger.Debug("Hash of stored public key calculated")

	// Calculate the hash of the provided public key
	providedKeyHash := sha256.Sum256(publicKey)
	logger.Debug("Hash of provided public key calculated")

	// Compare the two hashes directly
	if storedKeyHash == providedKeyHash {
		logger.Info("Public key hashes match")
		return true, nil
	} else {
		logger.Warn("Public key hashes do not match")
		return false, nil
	}
}

// GetCurrentUser identifies the current user by matching the public key with the manifest
func GetCurrentUser(userPublicKeyList *encryption.UserPublicKeyList) (string, error) {
	logger := utils.GetLogger()
	logger.Debug("Identifying the current user")

	// Retrieve the current user's public key
	currentUserKey, err := RetrievePublicKey()
	if err != nil {
		logger.Error("Failed to retrieve the current user's public key", "error", err)
		return "", fmt.Errorf("failed to retrieve the current user's public key: %w", err)
	}

	// Iterate through the list of users passed to the function
	for _, userPublicKey := range userPublicKeyList.Users {
		if strings.EqualFold(string(currentUserKey), string(userPublicKey.PublicKey)) {
			logger.Info("Current user identified", "username", userPublicKey.Username)
			return userPublicKey.Username, nil
		}
	}

	logger.Warn("No matching user found for the current public key")
	return "", fmt.Errorf("no matching user found for the current public key")
}

package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/denisbrodbeck/machineid"
	"github.com/maniac-en/locknkey/pkg/utils"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/pbkdf2"
)

func EncryptAESKey(aesKey []byte, publicKey []byte) ([]byte, error) {
	logger := utils.GetLogger()

	logger.Debug("Decoding public key")
	block, _ := pem.Decode(publicKey)
	if block == nil {
		logger.Error("Failed to parse PEM block containing the public key")
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		logger.Error("Failed to parse public key", "error", err)
		return nil, err
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, aesKey)
	if err != nil {
		logger.Error("Failed to encrypt AES key", "error", err)
		return nil, err
	}

	logger.Info("AES key encrypted successfully")
	return encryptedKey, nil
}

func DecryptAESKey(encryptedKey []byte, privateKey []byte) ([]byte, error) {
	logger := utils.GetLogger()

	logger.Debug("Decoding private key")
	block, _ := pem.Decode(privateKey)
	if block == nil {
		logger.Error("Failed to parse PEM block containing the private key")
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logger.Error("Failed to parse private key", "error", err)
		return nil, err
	}

	decryptedKey, err := rsa.DecryptPKCS1v15(rand.Reader, priv, encryptedKey)
	if err != nil {
		logger.Error("Failed to decrypt AES key", "error", err)
		return nil, err
	}

	logger.Debug("AES key decrypted successfully")
	return decryptedKey, nil
}

// getHashedMachineID retrieves a unique hashed hardware ID for the system
func getHashedMachineID() (string, error) {
	hashedID, err := machineid.ProtectedID("LockNKey")
	if err != nil {
		return "", fmt.Errorf("failed to get hashed machine ID: %w", err)
	}
	return hashedID, nil
}

// generateSystemBoundKey derives an AES key based on the hashed machine ID
func generateSystemBoundKey() ([]byte, error) {
	hashedID, err := getHashedMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get hashed machine ID: %w", err)
	}

	salt := []byte(hashedID)
	return pbkdf2.Key([]byte(hashedID), salt, 4096, 32, sha256.New), nil
}

// generateAndStoreKeys generates a system-bound RSA key pair and stores the private key securely
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

	hashedID, err := getHashedMachineID()
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

func RetrievePrivateKey() ([]byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Retrieving user's Private Key")

	// Retrieve the machine ID
	hashedID, err := getHashedMachineID()
	if err != nil {
		logger.Error("Failed to retrieve machine ID", "error", err)
		return nil, fmt.Errorf("failed to retrieve machine ID: %w", err)
	}
	logger.Debug("Machine ID retrieved", "hashedID", hashedID)

	// Get the private key PEM from the keyring
	privateKeyPEM, err := keyring.Get("LockNKey", "privateKey_"+hashedID)
	if err != nil {
		logger.Error("Failed to retrieve private key", "error", err)
		return nil, fmt.Errorf("failed to retrieve private key: %w", err)
	}
	logger.Info("Private key retrieved securely.")

	// Convert the PEM string to a byte slice
	privateKeyBytes := []byte(privateKeyPEM)

	return privateKeyBytes, nil
}

func RetrievePublicKey() ([]byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Retrieving user's Public Key")

	// Retrieve the machine ID
	hashedID, err := getHashedMachineID()
	if err != nil {
		logger.Error("Failed to retrieve machine ID", "error", err)
		return nil, fmt.Errorf("failed to retrieve machine ID: %w", err)
	}
	logger.Debug("Machine ID retrieved", "hashedID", hashedID)

	// Get the public key PEM from the keyring
	publicKeyPEM, err := keyring.Get("LockNKey", "publicKey_"+hashedID)
	if err != nil {
		logger.Error("Failed to retrieve public key", "error", err)
		return nil, fmt.Errorf("failed to retrieve public key: %w", err)
	}
	logger.Info("Public key retrieved securely.")

	// Convert the PEM string to a byte slice
	publicKeyBytes := []byte(publicKeyPEM)

	return publicKeyBytes, nil
}

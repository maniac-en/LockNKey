package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/maniac-en/locknkey/pkg/utils"
)

// UserPublicKey holds the information of a user and their public key
type UserPublicKey struct {
	Username  string
	PublicKey []byte
}

// UserPublicKeyList is a collection of UserPublicKey instances
type UserPublicKeyList struct {
	Users []UserPublicKey
}

func EncryptAESKeyForMultipleUsers(aesKey []byte, publicKeyPaths []string) ([][]byte, error) {
	var encryptedKeys [][]byte
	for _, publicKeyPath := range publicKeyPaths {
		publicKey, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, err
		}

		encryptedKey, err := EncryptAESKey(aesKey, publicKey)
		if err != nil {
			return nil, err
		}

		encryptedKeys = append(encryptedKeys, encryptedKey)
	}
	return encryptedKeys, nil
}

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

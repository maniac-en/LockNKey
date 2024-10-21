package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/maniac-en/locknkey/pkg/encryption"
	"github.com/maniac-en/locknkey/pkg/logutil"
)

func main() {
	// Initialize logger
	if err := logutil.InitLogger("locknkey_logs.json"); err != nil {
		fmt.Printf("Error initializing logger: %v\n", err)
		return
	}

	logger := logutil.GetLogger()
	logger.Info("LockNKey started")

	if len(os.Args) < 2 {
		logger.Warn("Insufficient arguments provided")
		fmt.Println("Usage: locknkey <command> [arguments]")
		return
	}

	command := os.Args[1]
	switch command {
	case "encrypt", "encrypt-dir":
		logger.Debug("Encrypt command detected", "command", command)
		if len(os.Args) < 4 {
			logger.Warn("Insufficient arguments for encrypt command", "command", command)
			fmt.Printf("Usage: locknkey %s <path> <public_key> <output_encrypted_aes_key>\n", command)
			return
		}

		path := os.Args[2]
		publicKeyPath := os.Args[3]
		outputAESKeyPath := os.Args[4]

		if err := handleEncryption(command, path, publicKeyPath, outputAESKeyPath); err != nil {
			logger.Error("Encryption failed", "error", err)
			return
		}

	case "decrypt", "decrypt-dir":
		logger.Debug("Decrypt command detected", "command", command)
		if len(os.Args) < 5 {
			logger.Warn("Insufficient arguments for decrypt command", "command", command)
			fmt.Printf("Usage: locknkey %s <encrypted_path> <private_key> <encrypted_aes_key>\n", command)
			return
		}

		encryptedPath := os.Args[2]
		privateKeyPath := os.Args[3]
		encryptedAESKeyPath := os.Args[4]

		if err := handleDecryption(command, encryptedPath, privateKeyPath, encryptedAESKeyPath); err != nil {
			logger.Error("Decryption failed", "error", err)
			return
		}

	default:
		logger.Warn("Unknown command", "command", command)
		fmt.Println("Unknown command")
	}
}

// handleEncryption handles both file and directory encryption based on the command
func handleEncryption(command, path, publicKeyPath, outputAESKeyPath string) error {
	logger := logutil.GetLogger()

	logger.Debug("Loading public key", "publicKeyPath", publicKeyPath)
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		logger.Error("Error reading public key", "error", err)
		return fmt.Errorf("error reading public key: %v", err)
	}

	logger.Debug("Generating AES key")
	aesKey := make([]byte, 32) // AES-256 key size
	if _, err = rand.Read(aesKey); err != nil {
		logger.Error("Error generating AES key", "error", err)
		return fmt.Errorf("error generating AES key: %v", err)
	}

	logger.Debug("Encrypting AES key")
	encryptedAESKey, err := encryption.EncryptAESKey(aesKey, publicKey)
	if err != nil {
		logger.Error("Error encrypting AES key", "error", err)
		return fmt.Errorf("error encrypting AES key: %v", err)
	}

	logger.Debug("Saving encrypted AES key", "outputAESKeyPath", outputAESKeyPath)
	if err := os.WriteFile(outputAESKeyPath, encryptedAESKey, 0644); err != nil {
		logger.Error("Error saving encrypted AES key", "error", err)
		return fmt.Errorf("error saving encrypted AES key: %v", err)
	}

	// Determine if encrypting a file or directory
	if command == "encrypt" {
		logger.Debug("Encrypting file", "path", path)
		err = encryption.EncryptFile(path, aesKey)
	} else if command == "encrypt-dir" {
		logger.Debug("Encrypting directory", "path", path)
		err = encryption.EncryptDirectory(path, aesKey)
	}
	if err != nil {
		logger.Error("Error during encryption", "error", err)
		return fmt.Errorf("error during encryption: %v", err)
	}

	return nil
}

// handleDecryption handles both file and directory decryption based on the command
func handleDecryption(command, encryptedPath, privateKeyPath, encryptedAESKeyPath string) error {
	logger := logutil.GetLogger()

	logger.Debug("Loading private key", "privateKeyPath", privateKeyPath)
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		logger.Error("Error reading private key", "error", err)
		return fmt.Errorf("error reading private key: %v", err)
	}

	logger.Debug("Loading encrypted AES key", "encryptedAESKeyPath", encryptedAESKeyPath)
	encryptedAESKey, err := os.ReadFile(encryptedAESKeyPath)
	if err != nil {
		logger.Error("Error reading encrypted AES key", "error", err)
		return fmt.Errorf("error reading encrypted AES key: %v", err)
	}

	logger.Debug("Decrypting AES key")
	aesKey, err := encryption.DecryptAESKey(encryptedAESKey, privateKey)
	if err != nil {
		logger.Error("Error decrypting AES key", "error", err)
		return fmt.Errorf("error decrypting AES key: %v", err)
	}

	// Determine if decrypting a file or directory
	if command == "decrypt" {
		err = encryption.DecryptFile(encryptedPath, aesKey)
	} else if command == "decrypt-dir" {
		err = encryption.DecryptDirectory(encryptedPath, aesKey)
	}
	if err != nil {
		logger.Error("Error during decryption", "error", err)
		return fmt.Errorf("error during decryption: %v", err)
	}

	return nil
}

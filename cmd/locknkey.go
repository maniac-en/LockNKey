package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/maniac-en/locknkey/pkg/authentication"
	"github.com/maniac-en/locknkey/pkg/encryption"
	"github.com/maniac-en/locknkey/pkg/utils"
)

func main() {
	if err := utils.InitLogger("locknkey_logs.json"); err != nil {
		fmt.Printf("Error initializing logger: %v\n", err)
		return
	}

	logger := utils.GetLogger()
	logger.Info("Application started")

	if len(os.Args) < 2 {
		logger.Warn("No command provided")
		fmt.Println("Usage: locknkey <command> [arguments]")
		return
	}

	command := os.Args[1]
	switch command {
	case "setup":
		logger.Debug("Running setup command")
		if err := authentication.RunSetup(); err != nil {
			logger.Error("Setup failed", "error", err)
			return
		}

	case "encrypt", "encrypt-dir":
		logger.Debug("Encrypt command detected", "command", command)
		if len(os.Args) < 4 {
			logger.Warn("Insufficient arguments for encrypt command", "command", command)
			fmt.Printf("Usage: locknkey %s <path> <output_encrypted_aes_key>\n", command)
			return
		}

		path := os.Args[2]
		outputAESKeyPath := os.Args[3]

		// TODO: needs to be reworked to use the public keys from object storage
		publicKey, err := encryption.RetrievePublicKey()
		if err != nil {
			logger.Error("Failed to retrieve public key", "error", err)
			fmt.Println("Error retrieving public key:", err)
			return
		}

		if err := handleEncryption(command, path, outputAESKeyPath, publicKey); err != nil {
			logger.Error("Encryption process failed", "error", err)
			return
		}

	case "decrypt", "decrypt-dir":
		logger.Debug("Decrypt command detected", "command", command)
		if len(os.Args) < 4 {
			logger.Warn("Insufficient arguments for decrypt command", "command", command)
			fmt.Printf("Usage: locknkey %s <encrypted_path> <encrypted_aes_key>\n", command)
			return
		}

		encryptedPath := os.Args[2]
		encryptedAESKeyPath := os.Args[3]

		privateKey, err := encryption.RetrievePrivateKey()
		if err != nil {
			logger.Error("Failed to retrieve private key", "error", err)
			fmt.Println("Error retrieving private key:", err)
			return
		}

		if err := handleDecryption(command, encryptedPath, encryptedAESKeyPath, privateKey); err != nil {
			logger.Error("Decryption process failed", "error", err)
			return
		}

	default:
		logger.Warn("Unknown command", "command", command)
		fmt.Println("Unknown command")
	}
}

func handleEncryption(command, path, outputAESKeyPath string, publicKey []byte) error {
	logger := utils.GetLogger()

	logger.Debug("Generating AES key")
	aesKey := make([]byte, 32) // AES-256 key size
	if n, err := rand.Read(aesKey); err != nil || n != len(aesKey) {
		logger.Error("Failed to generate AES key", "error", err)
		return fmt.Errorf("failed to generate AES key: %v", err)
	}

	logger.Debug("Encrypting AES key")
	encryptedAESKey, err := encryption.EncryptAESKey(aesKey, publicKey)
	if err != nil {
		logger.Error("Failed to encrypt AES key", "error", err)
		return fmt.Errorf("failed to encrypt AES key: %v", err)
	}

	logger.Debug("Saving encrypted AES key", "path", outputAESKeyPath)
	if err := os.WriteFile(outputAESKeyPath, encryptedAESKey, 0644); err != nil {
		logger.Error("Failed to save encrypted AES key", "error", err)
		return fmt.Errorf("failed to save encrypted AES key: %v", err)
	}

	if command == "encrypt" {
		logger.Debug("Encrypting file", "path", path)
		err = encryption.EncryptFile(path, aesKey)
	} else if command == "encrypt-dir" {
		logger.Debug("Encrypting directory", "path", path)
		err = encryption.EncryptDirectory(path, aesKey)
	}
	if err != nil {
		logger.Error("Encryption operation failed", "error", err)
		return fmt.Errorf("encryption operation failed: %v", err)
	}

	return nil
}

func handleDecryption(command, encryptedPath, encryptedAESKeyPath string, privateKey []byte) error {
	logger := utils.GetLogger()

	logger.Debug("Reading encrypted AES key", "path", encryptedAESKeyPath)
	encryptedAESKey, err := os.ReadFile(encryptedAESKeyPath)
	if err != nil {
		logger.Error("Failed to read encrypted AES key", "error", err)
		return fmt.Errorf("failed to read encrypted AES key: %v", err)
	}

	logger.Debug("Decrypting AES key")
	aesKey, err := encryption.DecryptAESKey(encryptedAESKey, privateKey)
	if err != nil {
		logger.Error("Failed to decrypt AES key", "error", err)
		return fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	if command == "decrypt" {
		err = encryption.DecryptFile(encryptedPath, aesKey)
	} else if command == "decrypt-dir" {
		err = encryption.DecryptDirectory(encryptedPath, aesKey)
	}
	if err != nil {
		logger.Error("Decryption operation failed", "error", err)
		return fmt.Errorf("decryption operation failed: %v", err)
	}

	return nil
}

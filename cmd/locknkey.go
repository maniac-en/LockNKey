package main

import (
	"crypto/rand"
	"fmt"
	"github.com/maniac-en/locknkey/pkg/encryption"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: locknkey <command> [arguments]")
		return
	}

	switch os.Args[1] {
	case "encrypt":
		if len(os.Args) < 4 {
			fmt.Println("Usage: locknkey encrypt <file> <public_key> <output_encrypted_aes_key>")
			return
		}

		plainFilePath := os.Args[2]
		publicKeyPath := os.Args[3]
		outputAESKeyPath := os.Args[4]

		// Load public key
		publicKey, err := os.ReadFile(publicKeyPath)
		if err != nil {
			fmt.Printf("Error reading public key: %v\n", err)
			return
		}

		// Generate a new AES key
		aesKey := make([]byte, 32) // AES-256 key size
		_, err = rand.Read(aesKey)
		if err != nil {
			fmt.Printf("Error generating AES key: %v\n", err)
			return
		}

		// Encrypt the file
		err = encryption.EncryptFile(plainFilePath, aesKey)
		if err != nil {
			fmt.Printf("Error encrypting file: %v\n", err)
			return
		}

		// Encrypt the AES key using the public key
		encryptedAESKey, err := encryption.EncryptAESKey(aesKey, publicKey)
		if err != nil {
			fmt.Printf("Error encrypting AES key: %v\n", err)
			return
		}

		// Save the encrypted AES key
		err = os.WriteFile(outputAESKeyPath, encryptedAESKey, 0644)
		if err != nil {
			fmt.Printf("Error saving encrypted AES key: %v\n", err)
			return
		}

		fmt.Printf("File \"%s\" encrypted successfully!\n", plainFilePath)

	case "decrypt":
		if len(os.Args) < 5 {
			fmt.Println("Usage: locknkey decrypt <file> <private_key> <encrypted_aes_key>")
			return
		}

		encryptedFilePath := os.Args[2]
		privateKeyPath := os.Args[3]
		encryptedAESKeyPath := os.Args[4]

		// Load private key
		privateKey, err := os.ReadFile(privateKeyPath)
		if err != nil {
			fmt.Printf("Error reading private key: %v\n", err)
			return
		}

		// Load encrypted AES key
		encryptedAESKey, err := os.ReadFile(encryptedAESKeyPath)
		if err != nil {
			fmt.Printf("Error reading encrypted AES key: %v\n", err)
			return
		}

		// Decrypt AES key
		aesKey, err := encryption.DecryptAESKey(encryptedAESKey, privateKey)
		if err != nil {
			fmt.Printf("Error decrypting AES key: %v\n", err)
			return
		}

		// Decrypt file
		err = encryption.DecryptFile(encryptedFilePath, aesKey)
		if err != nil {
			fmt.Printf("Error decrypting file: %v\n", err)
			return
		}

		fmt.Printf("File \"%s\" decrypted successfully!\n", encryptedFilePath)

	case "encrypt-dir":
		if len(os.Args) < 4 {
			fmt.Println("Usage: locknkey encrypt-dir <directory> <public_key> <output_encrypted_aes_key>")
			return
		}

		directoryPath := os.Args[2]
		publicKeyPath := os.Args[3]
		outputAESKeyPath := os.Args[4]

		// Load public key
		publicKey, err := os.ReadFile(publicKeyPath)
		if err != nil {
			fmt.Printf("Error reading public key: %v\n", err)
			return
		}

		// Generate a new AES key
		aesKey := make([]byte, 32) // AES-256 key size
		_, err = rand.Read(aesKey)
		if err != nil {
			fmt.Printf("Error generating AES key: %v\n", err)
			return
		}

		// Encrypt the directory
		err = encryption.EncryptDirectory(directoryPath, aesKey)
		if err != nil {
			fmt.Printf("Error encrypting directory: %v\n", err)
			return
		}

		// Encrypt the AES key using the public key
		encryptedAESKey, err := encryption.EncryptAESKey(aesKey, publicKey)
		if err != nil {
			fmt.Printf("Error encrypting AES key: %v\n", err)
			return
		}

		// Save the encrypted AES key
		err = os.WriteFile(outputAESKeyPath, encryptedAESKey, 0644)
		if err != nil {
			fmt.Printf("Error saving encrypted AES key: %v\n", err)
			return
		}

		fmt.Printf("File \"%s\" encrypted successfully!\n", directoryPath)

	case "decrypt-dir":
		if len(os.Args) < 5 {
			fmt.Println("Usage: locknkey decrypt-dir <encrypted_file> <private_key> <encrypted_aes_key>")
			return
		}

		encryptedDirPath := os.Args[2]
		privateKeyPath := os.Args[3]
		encryptedAESKeyPath := os.Args[4]

		// Load private key
		privateKey, err := os.ReadFile(privateKeyPath)
		if err != nil {
			fmt.Printf("Error reading private key: %v\n", err)
			return
		}

		// Load encrypted AES key
		encryptedAESKey, err := os.ReadFile(encryptedAESKeyPath)
		if err != nil {
			fmt.Printf("Error reading encrypted AES key: %v\n", err)
			return
		}

		// Decrypt AES key
		aesKey, err := encryption.DecryptAESKey(encryptedAESKey, privateKey)
		if err != nil {
			fmt.Printf("Error decrypting AES key: %v\n", err)
			return
		}

		// Decrypt directory
		err = encryption.DecryptDirectory(encryptedDirPath, aesKey)
		if err != nil {
			fmt.Printf("Error decrypting file: %v\n", err)
			return
		}

		fmt.Printf("File \"%s\" decrypted successfully!\n", encryptedDirPath)

	default:
		fmt.Println("Unknown command")
	}
}

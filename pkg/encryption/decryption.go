package encryption

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func DecryptAESKey(encryptedKey []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Type assertion to get the RSA private key from the interface{}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	decryptedKey, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPriv, encryptedKey)
	if err != nil {
		return nil, err
	}

	return decryptedKey, nil
}

func DecryptFile(filePath string, key []byte) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	fileData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	if len(fileData) < nonceSize {
		return errors.New("file data is too short to contain nonce")
	}

	nonce, ciphertext := fileData[:nonceSize], fileData[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Remove ".enc" extension and save the decrypted file
	newFilePath := strings.TrimSuffix(filePath, ".enc")
	if newFilePath == filePath {
		return errors.New("file does not have a .enc extension")
	}

	return os.WriteFile(newFilePath, decrypted, 0644)
}

func DecryptDirectory(encryptedFilePath string, key []byte) error {
	// Decrypt the file first
	err := DecryptFile(encryptedFilePath, key)
	if err != nil {
		return err
	}

	// Remove the ".enc" suffix to get the decrypted ZIP path
	zipFilePath := strings.TrimSuffix(encryptedFilePath, ".enc")
	if zipFilePath == encryptedFilePath {
		return errors.New("file does not have a .enc extension")
	}

	// Open the ZIP file
	zipFile, err := os.Open(zipFilePath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Get the file size
	zipFileInfo, err := zipFile.Stat()
	if err != nil {
		return err
	}
	zipFileSize := zipFileInfo.Size()

	zipReader, err := zip.NewReader(zipFile, zipFileSize)
	if err != nil {
		return err
	}

	// Extract files
	for _, file := range zipReader.File {
		fpath := filepath.Join(filepath.Dir(zipFilePath), file.Name)

		// Ensure directory structure
		if file.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Create directories if they don't exist
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer outFile.Close()

		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		_, err = io.Copy(outFile, rc)
		if err != nil {
			return err
		}
	}

	// Optionally, remove the ZIP file after extraction
	os.Remove(zipFilePath)

	return nil
}

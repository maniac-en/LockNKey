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
	"github.com/maniac-en/locknkey/pkg/logutil"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func DecryptAESKey(encryptedKey []byte, privateKey []byte) ([]byte, error) {
	logger := logutil.GetLogger()

	logger.Debug("Decoding private key")
	block, _ := pem.Decode(privateKey)
	if block == nil {
		logger.Error("Failed to parse PEM block containing the private key")
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.Error("Failed to parse private key", "error", err)
		return nil, err
	}

	// Type assertion to get the RSA private key from the interface{}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		logger.Error("Not an RSA private key")
		return nil, errors.New("not an RSA private key")
	}

	decryptedKey, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPriv, encryptedKey)
	if err != nil {
		logger.Error("Failed to decrypt AES key", "error", err)
		return nil, err
	}

	logger.Debug("AES key decrypted successfully")
	return decryptedKey, nil
}

func DecryptFile(filePath string, key []byte) error {
	logger := logutil.GetLogger()

	logger.Debug("Opening encrypted file", "filePath", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open encrypted file", "filePath", filePath, "error", err)
		return err
	}
	defer file.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("Failed to create AES cipher", "error", err)
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error("Failed to create GCM cipher mode", "error", err)
		return err
	}

	nonceSize := gcm.NonceSize()
	fileData, err := io.ReadAll(file)
	if err != nil {
		logger.Error("Failed to read encrypted file", "filePath", filePath, "error", err)
		return err
	}

	if len(fileData) < nonceSize {
		logger.Error("File data is too short to contain nonce", "filePath", filePath)
		return errors.New("file data is too short to contain nonce")
	}

	nonce, ciphertext := fileData[:nonceSize], fileData[nonceSize:]

	logger.Debug("Decrypting file content")
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logger.Error("Failed to decrypt file content", "error", err)
		return err
	}

	newFilePath := strings.TrimSuffix(filePath, ".enc")
	if newFilePath == filePath {
		logger.Error("File does not have a .enc extension", "filePath", filePath)
		return errors.New("file does not have a .enc extension")
	}

	logger.Debug("Saving decrypted file", "newFilePath", newFilePath)
	if err := os.WriteFile(newFilePath, decrypted, 0644); err != nil {
		logger.Error("Failed to save decrypted file", "newFilePath", newFilePath, "error", err)
		return err
	}

	logger.Info("File decrypted successfully", "filePath", newFilePath)
	return nil
}

func DecryptDirectory(encryptedFilePath string, key []byte) error {
	logger := logutil.GetLogger()

	logger.Debug("Decrypting directory", "encryptedFilePath", encryptedFilePath)
	// Decrypt the file first
	err := DecryptFile(encryptedFilePath, key)
	if err != nil {
		logger.Error("Failed to decrypt file", "encryptedFilePath", encryptedFilePath, "error", err)
		return err
	}

	// Remove the ".enc" suffix to get the decrypted ZIP path
	zipFilePath := strings.TrimSuffix(encryptedFilePath, ".enc")
	if zipFilePath == encryptedFilePath {
		logger.Error("File does not have a .enc extension", "encryptedFilePath", encryptedFilePath)
		return errors.New("file does not have a .enc extension")
	}

	logger.Debug("Opening decrypted ZIP file", "zipFilePath", zipFilePath)
	zipFile, err := os.Open(zipFilePath)
	if err != nil {
		logger.Error("Failed to open ZIP file", "zipFilePath", zipFilePath, "error", err)
		return err
	}
	defer zipFile.Close()

	zipFileInfo, err := zipFile.Stat()
	if err != nil {
		logger.Error("Failed to get ZIP file information", "zipFilePath", zipFilePath, "error", err)
		return err
	}
	zipFileSize := zipFileInfo.Size()

	zipReader, err := zip.NewReader(zipFile, zipFileSize)
	if err != nil {
		logger.Error("Failed to create ZIP reader", "zipFilePath", zipFilePath, "error", err)
		return err
	}

	// Extract files
	for _, file := range zipReader.File {
		fpath := filepath.Join(filepath.Dir(zipFilePath), file.Name)

		if file.FileInfo().IsDir() {
			logger.Debug("Creating directory", "directory", fpath)
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		logger.Debug("Creating file", "file", fpath)
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			logger.Error("Failed to create directories for file", "file", fpath, "error", err)
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			logger.Error("Failed to create output file", "file", fpath, "error", err)
			return err
		}
		defer outFile.Close()

		rc, err := file.Open()
		if err != nil {
			logger.Error("Failed to open file in ZIP archive", "file", file.Name, "error", err)
			return err
		}
		defer rc.Close()

		_, err = io.Copy(outFile, rc)
		if err != nil {
			logger.Error("Failed to copy file content", "file", fpath, "error", err)
			return err
		}
	}

	logger.Debug("Removing temporary ZIP file", "zipFilePath", zipFilePath)
	os.Remove(zipFilePath)

	logger.Info("Directory decrypted successfully", "path", encryptedFilePath)
	return nil
}

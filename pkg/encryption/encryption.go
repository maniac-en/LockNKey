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
)

func GenerateRSAKeys(bits int) (privateKey *rsa.PrivateKey, publicKey []byte, err error) {
	logger := logutil.GetLogger()

	logger.Debug("Generating RSA keys", "bits", bits)
	privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		logger.Error("Failed to generate RSA keys", "error", err)
		return nil, nil, err
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	logger.Info("RSA keys generated successfully")
	return privateKey, publicKey, nil
}

func EncryptAESKey(aesKey []byte, publicKey []byte) ([]byte, error) {
	logger := logutil.GetLogger()

	logger.Debug("Decoding public key")
	block, _ := pem.Decode(publicKey)
	if block == nil {
		logger.Error("Failed to parse PEM block containing the public key")
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Error("Failed to parse public key", "error", err)
		return nil, err
	}

	// Type assertion to get the RSA public key from the interface{}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		logger.Error("Not an RSA public key")
		return nil, errors.New("not an RSA public key")
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, aesKey)
	if err != nil {
		logger.Error("Failed to encrypt AES key", "error", err)
		return nil, err
	}

	logger.Info("AES key encrypted successfully")
	return encryptedKey, nil
}

func EncryptFile(filePath string, key []byte) error {
	logger := logutil.GetLogger()

	logger.Debug("Opening file for encryption", "filePath", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open file for encryption", "filePath", filePath, "error", err)
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		logger.Error("Failed to generate nonce", "error", err)
		return err
	}

	logger.Debug("Reading file content", "filePath", filePath)
	fileData, err := io.ReadAll(file)
	if err != nil {
		logger.Error("Failed to read file content", "filePath", filePath, "error", err)
		return err
	}

	encrypted := gcm.Seal(nonce, nonce, fileData, nil)

	newFilePath := filePath + ".enc"
	logger.Debug("Writing encrypted file", "newFilePath", newFilePath)
	if err := os.WriteFile(newFilePath, encrypted, 0644); err != nil {
		logger.Error("Failed to write encrypted file", "newFilePath", newFilePath, "error", err)
		return err
	}

	logger.Info("File encrypted successfully", "filePath", newFilePath)
	return nil
}

func EncryptDirectory(dirPath string, key []byte) error {
	logger := logutil.GetLogger()

	logger.Debug("Creating temporary ZIP file for directory", "dirPath", dirPath)
	zipFile, err := os.Create(dirPath + ".zip")
	if err != nil {
		logger.Error("Failed to create temporary ZIP file", "dirPath", dirPath, "error", err)
		return err
	}
	defer zipFile.Close()

	// Add files to the ZIP
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error while walking directory", "path", path, "error", err)
			return err
		}

		// Skip the directory itself
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(filepath.Dir(dirPath), path)
		if err != nil {
			logger.Error("Failed to get relative path", "path", path, "error", err)
			return err
		}

		logger.Debug("Adding file to ZIP", "file", relPath)
		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			logger.Error("Failed to create ZIP entry", "file", relPath, "error", err)
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			logger.Error("Failed to open file for zipping", "file", path, "error", err)
			return err
		}
		defer file.Close()

		if _, err = io.Copy(zipEntry, file); err != nil {
			logger.Error("Failed to copy file content to ZIP", "file", relPath, "error", err)
			return err
		}
		return nil
	})

	if err != nil {
		logger.Error("Error occurred while zipping directory", "dirPath", dirPath, "error", err)
		return err
	}

	zipWriter.Close()
	zipFilePath := dirPath + ".zip"
	logger.Debug("Encrypting ZIP file", "zipFilePath", zipFilePath)
	err = EncryptFile(zipFilePath, key)
	if err != nil {
		logger.Error("Failed to encrypt ZIP file", "zipFilePath", zipFilePath, "error", err)
		return err
	}

	logger.Debug("Removing temporary ZIP file", "zipFilePath", zipFilePath)
	os.Remove(zipFilePath)

	logger.Info("Directory encrypted successfully", "dirPath", dirPath)
	return nil
}

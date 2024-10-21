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
)

func GenerateRSAKeys(bits int) (privateKey *rsa.PrivateKey, publicKey []byte, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKey, publicKey, nil
}

func EncryptAESKey(aesKey []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Type assertion to get the RSA public key from the interface{}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, aesKey)
	if err != nil {
		return nil, err
	}
	return encryptedKey, nil
}

func EncryptFile(filePath string, key []byte) error {
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	fileData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	encrypted := gcm.Seal(nonce, nonce, fileData, nil)

	return os.WriteFile(filePath+".enc", encrypted, 0644)
}

func EncryptDirectory(dirPath string, key []byte) error {
	// Create a temporary ZIP file
	zipFile, err := os.Create(dirPath + ".zip")
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Add files to the ZIP
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the directory itself
		if info.IsDir() {
			return nil
		}

		// Create a file in the ZIP archive
		relPath, err := filepath.Rel(filepath.Dir(dirPath), path)
		if err != nil {
			return err
		}

		zipEntry, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(zipEntry, file)
		return err
	})

	if err != nil {
		return err
	}

	// Close the ZIP writer to finalize the archive
	zipWriter.Close()

	// Encrypt the ZIP file
	zipFilePath := dirPath + ".zip"
	err = EncryptFile(zipFilePath, key)
	if err != nil {
		return err
	}

	// Optionally, remove the temporary ZIP file after encryption
	os.Remove(zipFilePath)

	return nil
}

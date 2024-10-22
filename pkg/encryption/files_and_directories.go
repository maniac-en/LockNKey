package encryption

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/maniac-en/locknkey/pkg/utils"
)

func EncryptFile(filePath string, key []byte) error {
	logger := utils.GetLogger()

	logger.Debug("Opening file", "filePath", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open file", "filePath", filePath, "error", err)
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
		logger.Error("Failed to create GCM cipher", "error", err)
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
	logger.Debug("Writing encrypted content", "newFilePath", newFilePath)
	if err := os.WriteFile(newFilePath, encrypted, 0644); err != nil {
		logger.Error("Failed to write encrypted content", "newFilePath", newFilePath, "error", err)
		return err
	}

	logger.Info("File encryption successful", "filePath", newFilePath)
	return nil
}

func EncryptDirectory(dirPath string, key []byte) error {
	logger := utils.GetLogger()

	logger.Debug("Creating ZIP for directory", "dirPath", dirPath)
	zipFile, err := os.Create(dirPath + ".zip")
	if err != nil {
		logger.Error("Failed to create ZIP file", "dirPath", dirPath, "error", err)
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Directory walk error", "path", path, "error", err)
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(filepath.Dir(dirPath), path)
		if err != nil {
			logger.Error("Error obtaining relative path", "path", path, "error", err)
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
			logger.Error("Failed to open file", "file", path, "error", err)
			return err
		}
		defer file.Close()

		if _, err = io.Copy(zipEntry, file); err != nil {
			logger.Error("Error copying file content", "file", relPath, "error", err)
			return err
		}
		return nil
	})

	if err != nil {
		logger.Error("Error zipping directory", "dirPath", dirPath, "error", err)
		return err
	}

	zipWriter.Close()
	zipFilePath := dirPath + ".zip"
	logger.Debug("Encrypting ZIP", "zipFilePath", zipFilePath)
	err = EncryptFile(zipFilePath, key)
	if err != nil {
		logger.Error("Error encrypting ZIP file", "zipFilePath", zipFilePath, "error", err)
		return err
	}

	logger.Debug("Removing temporary ZIP", "zipFilePath", zipFilePath)
	os.Remove(zipFilePath)

	logger.Info("Directory encryption successful", "dirPath", dirPath)
	return nil
}

func DecryptFile(filePath string, key []byte) error {
	logger := utils.GetLogger()

	logger.Debug("Opening encrypted file", "filePath", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open encrypted file", "filePath", filePath, "error", err)
		return err
	}
	defer file.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("Error creating AES cipher", "error", err)
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error("Error creating GCM cipher mode", "error", err)
		return err
	}

	nonceSize := gcm.NonceSize()
	fileData, err := io.ReadAll(file)
	if err != nil {
		logger.Error("Error reading encrypted file", "filePath", filePath, "error", err)
		return err
	}

	if len(fileData) < nonceSize {
		logger.Error("File too short for nonce", "filePath", filePath)
		return errors.New("file too short for nonce")
	}

	nonce, ciphertext := fileData[:nonceSize], fileData[nonceSize:]

	logger.Debug("Decrypting file content")
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logger.Error("Error decrypting content", "error", err)
		return err
	}

	newFilePath := strings.TrimSuffix(filePath, ".enc")
	if newFilePath == filePath {
		logger.Error("File missing .enc extension", "filePath", filePath)
		return errors.New("file missing .enc extension")
	}

	logger.Debug("Writing decrypted content", "newFilePath", newFilePath)
	if err := os.WriteFile(newFilePath, decrypted, 0644); err != nil {
		logger.Error("Error saving decrypted content", "newFilePath", newFilePath, "error", err)
		return err
	}

	logger.Info("File decryption successful", "filePath", newFilePath)
	return nil
}

func DecryptDirectory(encryptedFilePath string, key []byte) error {
	logger := utils.GetLogger()

	logger.Debug("Decrypting directory", "encryptedFilePath", encryptedFilePath)
	err := DecryptFile(encryptedFilePath, key)
	if err != nil {
		logger.Error("Error decrypting file", "encryptedFilePath", encryptedFilePath, "error", err)
		return err
	}

	zipFilePath := strings.TrimSuffix(encryptedFilePath, ".enc")
	if zipFilePath == encryptedFilePath {
		logger.Error("File missing .enc extension", "encryptedFilePath", encryptedFilePath)
		return errors.New("file missing .enc extension")
	}

	logger.Debug("Opening ZIP", "zipFilePath", zipFilePath)
	zipFile, err := os.Open(zipFilePath)
	if err != nil {
		logger.Error("Failed to open ZIP", "zipFilePath", zipFilePath, "error", err)
		return err
	}
	defer zipFile.Close()

	zipFileInfo, err := zipFile.Stat()
	if err != nil {
		logger.Error("Error retrieving ZIP info", "zipFilePath", zipFilePath, "error", err)
		return err
	}
	zipFileSize := zipFileInfo.Size()

	zipReader, err := zip.NewReader(zipFile, zipFileSize)
	if err != nil {
		logger.Error("Error creating ZIP reader", "zipFilePath", zipFilePath, "error", err)
		return err
	}

	for _, file := range zipReader.File {
		fpath := filepath.Join(filepath.Dir(zipFilePath), file.Name)

		if file.FileInfo().IsDir() {
			logger.Debug("Creating directory", "directory", fpath)
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		logger.Debug("Creating file", "file", fpath)
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			logger.Error("Error creating file directories", "file", fpath, "error", err)
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			logger.Error("Error creating output file", "file", fpath, "error", err)
			return err
		}
		defer outFile.Close()

		rc, err := file.Open()
		if err != nil {
			logger.Error("Error opening file in ZIP", "file", file.Name, "error", err)
			return err
		}
		defer rc.Close()

		if _, err = io.Copy(outFile, rc); err != nil {
			logger.Error("Error copying file content", "file", fpath, "error", err)
			return err
		}
	}

	logger.Debug("Removing temporary ZIP", "zipFilePath", zipFilePath)
	os.Remove(zipFilePath)

	logger.Info("Directory decryption successful", "path", encryptedFilePath)
	return nil
}

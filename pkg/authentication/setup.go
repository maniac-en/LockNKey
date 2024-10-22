package authentication

import (
	"fmt"

	"github.com/maniac-en/locknkey/pkg/encryption"
	"github.com/maniac-en/locknkey/pkg/utils"
)

// RunSetup sets up the LockNKey system with necessary credentials and keys.
func RunSetup() error {
	logger := utils.GetLogger()
	logger.Info("Initiating LockNKey setup")

	accessKey, err := utils.SecurePrompt("Enter Object Storage access key: ")
	if err != nil {
		logger.Error("Failed to read Object Storage access key", "error", err)
		return fmt.Errorf("failed to read Object Storage access key: %w", err)
	}

	logger.Debug("Encrypting and storing Object Storage access key")
	if err := encryption.EncryptAndStoreToken(accessKey, "object_storage_access_key"); err != nil {
		logger.Error("Failed to encrypt and store Object Storage access key", "error", err)
		return fmt.Errorf("failed to encrypt and store Object Storage access key: %w", err)
	}

	logger.Info("Object Storage access key stored successfully")

	secretKey, err := utils.SecurePrompt("Enter Object Storage secret key: ")
	if err != nil {
		logger.Error("Failed to read Object Storage secret key", "error", err)
		return fmt.Errorf("failed to read Object Storage secret key: %w", err)
	}

	logger.Debug("Encrypting and storing Object Storage secret key")
	if err := encryption.EncryptAndStoreToken(secretKey, "object_storage_secret_key"); err != nil {
		logger.Error("Failed to encrypt and store Object Storage secret key", "error", err)
		return fmt.Errorf("failed to encrypt and store Object Storage secret key: %w", err)
	}

	logger.Info("Object Storage secret key stored successfully")

	_, publicKey, err := encryption.GenerateAndStoreKeys()
	if err != nil {
		logger.Error("Failed to generate or store keys", "error", err)
		return fmt.Errorf("failed to generate or store keys: %w", err)
	}

	// Register the public key
	if err := uploadPublicKey(publicKey); err != nil {
		logger.Error("Public key upload failed", "error", err)
		return fmt.Errorf("public key upload failed: %w", err)
	}

	logger.Info("Setup completed. LockNKey is now configured")
	return nil
}

// TODO
// uploadPublicKey uploads the public key to a remote storage or API endpoint for validation
func uploadPublicKey(_ []byte) error {
	logger := utils.GetLogger()
	logger.Debug("Uploading public key")

	return nil
	// // Placeholder URL: Replace with your endpoint where the public key should be uploaded
	// uploadURL := "https://your-secure-endpoint/uploadPublicKey"
	//
	// req, err := http.NewRequest("POST", uploadURL, strings.NewReader(string(publicKey)))
	// if err != nil {
	// 	logger.Error("Failed to create HTTP request for public key upload", "error", err)
	// 	return fmt.Errorf("failed to create HTTP request: %w", err)
	// }
	// req.Header.Set("Content-Type", "application/x-pem-file")
	//
	// client := &http.Client{}
	// resp, err := client.Do(req)
	// if err != nil {
	// 	logger.Error("HTTP request for public key upload failed", "error", err)
	// 	return fmt.Errorf("HTTP request for public key upload failed: %w", err)
	// }
	// defer resp.Body.Close()
	//
	// if resp.StatusCode != http.StatusOK {
	// 	logger.Error("Public key upload returned non-OK status", "status", resp.StatusCode)
	// 	return fmt.Errorf("public key upload failed with status code: %s", resp.Status)
	// }
	//
	// logger.Info("Public key uploaded successfully")
	// return nil
}

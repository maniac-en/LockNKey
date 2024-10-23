package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	// "net/http/httputil"

	"time"

	"github.com/maniac-en/locknkey/pkg/config"
	"github.com/maniac-en/locknkey/pkg/encryption"
	"github.com/maniac-en/locknkey/pkg/manifest"
	"github.com/maniac-en/locknkey/pkg/utils"
)

// PresignedURLRequest represents the JSON body for requesting a presigned URL.
type PresignedURLRequest struct {
	ExpiresIn int    `json:"expires_in"`
	Method    string `json:"method"`
	Name      string `json:"name"`
}

type CredentialsResponse struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

// TODO: Create the boilerplate manifest and upload it if no manifest exists
// already on the cloud
// PreSetup downloads the manifest.json file using a presigned URL
func PreSetup(apiKey string, cfg *config.Config) (*manifest.Manifest, error) {
	logger := utils.GetLogger()
	logger.Info("Starting PreSetup to download the manifest file")

	// Construct the API URL for requesting the presigned URL.
	url := fmt.Sprintf("%s/buckets/%s/%s/object-url", cfg.APIEndpoint, cfg.Region, cfg.BucketName)

	// Prepare the request payload.
	requestBody := PresignedURLRequest{
		ExpiresIn: 3600,
		Method:    "GET",
		Name:      cfg.ManifestFilePath,
	}

	// Convert the request payload to JSON.
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		logger.Error("Failed to marshal request body", "error", err)
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create the HTTP request.
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		logger.Error("Failed to create HTTP request", "error", err)
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers.
	req.Header.Set("accept", "application/json")
	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("content-type", "application/json")

	// reqDump, _ := httputil.DumpRequestOut(req, true)
	// fmt.Printf("REQUEST:\n%s\n\n", string(reqDump))

	// Execute the HTTP request.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)

	// respDump, err := httputil.DumpResponse(resp, true)
	// fmt.Printf("RESPONSE:\n%s\n\n", string(respDump))

	if err != nil {
		logger.Error("Failed to make API request", "error", err)
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the response status code is not OK (200).
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("API request failed", "status", resp.StatusCode, "response", string(body))
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response body to get the presigned URL.
	var responseData struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		logger.Error("Failed to decode API response", "error", err)
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	// Download and parse the manifest file using the presigned URL.
	manifest, err := fetchAndParseManifest(responseData.URL)
	if err != nil {
		logger.Error("Failed to download and parse manifest", "error", err)
		return nil, fmt.Errorf("failed to download and parse manifest: %w", err)
	}

	logger.Info("PreSetup completed successfully")
	return manifest, nil
}

// fetchAndParseManifest downloads the manifest JSON from the given URL and
// parses it into a Manifest struct.
func fetchAndParseManifest(url string) (*manifest.Manifest, error) {
	logger := utils.GetLogger()
	logger.Debug("Fetching manifest file from presigned URL", "url", url)

	// Fetch the file using the presigned URL.
	resp, err := http.Get(url)
	if err != nil {
		logger.Error("Failed to fetch the manifest file", "error", err)
		return nil, fmt.Errorf("failed to fetch the manifest file from URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("Failed to download manifest file", "status_code", resp.StatusCode)
		return nil, fmt.Errorf("failed to download manifest file, status code: %d", resp.StatusCode)
	}

	// Decode the response body directly into the manifest struct.
	var m manifest.Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		logger.Error("Failed to decode manifest JSON", "error", err)
		return nil, fmt.Errorf("failed to decode manifest JSON: %w", err)
	}

	logger.Info("Manifest file fetched and parsed successfully")
	return &m, nil
}

// RunSetup initializes the setup process for LockNKey
func RunSetup(apiKey string, manifestObj *manifest.Manifest, cfg *config.Config) ([]byte, string, error) {
	logger := utils.GetLogger()
	logger.Info("Initiating LockNKey setup")

	// TODO
	// Validate the API key
	// if !isValidAPIKey(apiKey) {
	// 	logger.Error("Invalid API Token provided")
	// 	return nil, "", fmt.Errorf("invalid API Token provided")
	// }
	// logger.Debug("API Token validated successfully")

	// Step 2: Prompt for username and ensure it's unique

	var username string
	for {
		inputUsername, err := utils.UnsecurePrompt("Enter a unique username: ")
		if err != nil {
			logger.Error("Failed to read username", "error", err)
			return nil, "", fmt.Errorf("failed to read username: %w", err)
		}

		// Check if the trimmed username is not empty before proceeding
		if inputUsername == "" {
			logger.Warn("Username cannot be empty. Please enter a valid username.")
			fmt.Println("Username cannot be empty. Please enter a valid username.")
			continue
		}

		// Check if the inputUsername already exists in the manifest
		if _, exists := manifestObj.Users[inputUsername]; !exists {
			username = inputUsername
			break // Exit the loop if username is unique
		}

		logger.Warn("Username already exists. Please choose a different one.")
		fmt.Println("Username already exists. Please choose a different one.")
	}
	logger.Debug("Unique username obtained", "username", username)

	// Step 3: Generate new access and secret keys for this user
	accessKey, secretKey, err := generateUserCredentials(apiKey, cfg, username)
	if err != nil {
		logger.Error("Failed to generate credentials for the user", "error", err)
		return nil, "", fmt.Errorf("failed to generate credentials for the user: %w", err)
	}

	// Step 4: Store the generated access and secret keys securely
	if err := encryption.EncryptAndStoreToken(accessKey, "object_storage_access_key_"+username); err != nil {
		logger.Error("Failed to store access key for the user", "username", username, "error", err)
		return nil, "", fmt.Errorf("failed to store access key for the user: %w", err)
	}
	if err := encryption.EncryptAndStoreToken(secretKey, "object_storage_secret_key_"+username); err != nil {
		logger.Error("Failed to store secret key for the user", "username", username, "error", err)
		return nil, "", fmt.Errorf("failed to store secret key for the user: %w", err)
	}
	logger.Info("Access and secret keys stored securely for the user", "username", username)

	// Step 5: Generate and store the RSA key pair for the user
	_, publicKey, err := GenerateAndStoreKeys()
	if err != nil {
		logger.Error("Failed to generate or store keys for the user", "error", err)
		return nil, "", fmt.Errorf("failed to generate or store keys for the user: %w", err)
	}
	logger.Info("RSA keys generated and stored for the user", "username", username)

	// Step 6: Return the public key to the caller
	logger.Info("Setup completed for the user", "username", username)
	return publicKey, username, nil
}

// generateUserCredentials interacts with the API to generate new access and secret keys for a user
func generateUserCredentials(apiKey string, cfg *config.Config, username string) (string, string, error) {
	logger := utils.GetLogger()
	logger.Debug("Generating user credentials")

	// Prepare the API URL and payload using the configuration values
	apiURL := fmt.Sprintf("%s/keys", cfg.APIEndpoint)

	// Prepare the payload using the bucket name and region from config
	payload := map[string]interface{}{
		"bucket_access": []map[string]string{
			{
				"bucket_name": cfg.BucketName,
				"permissions": "read_write",
				"region":      cfg.Region,
			},
		},
		"label": username,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal payload", "error", err)
		return "", "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create a new HTTP request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		logger.Error("Failed to create HTTP request", "error", err)
		return "", "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set the necessary headers
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", apiKey))

	// Set up the HTTP client with a timeout
	client := &http.Client{Timeout: 10 * time.Second}

	// Execute the HTTP request
	res, err := client.Do(req)

	if err != nil {
		logger.Error("Failed to execute HTTP request", "error", err)
		return "", "", fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer res.Body.Close()

	// Read and parse the response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Error("Failed to read response body", "error", err)
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for HTTP errors
	if res.StatusCode != http.StatusOK {
		logger.Error("API responded with error", "status", res.StatusCode, "body", string(body))
		return "", "", fmt.Errorf("API responded with status: %d", res.StatusCode)
	}

	// Parse the JSON response to extract the credentials
	var credentials CredentialsResponse
	if err := json.Unmarshal(body, &credentials); err != nil {
		logger.Error("Failed to parse response", "error", err)
		return "", "", fmt.Errorf("failed to parse response: %w", err)
	}

	logger.Info("User credentials generated successfully")
	return credentials.AccessKey, credentials.SecretKey, nil
}

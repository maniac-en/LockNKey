package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/maniac-en/locknkey/pkg/utils"
)

type Config struct {
	BucketName        string `json:"bucket_name"`
	ManifestFilePath  string `json:"manifest_file_path"`
	S3Endpoint        string `json:"s3_endpoint"`
	APIEndpoint       string `json:"api_endpoint"`
	Region            string `json:"region"`
	LogFilePath       string `json:"log_file_path"`
	PublicKeysDirPath string `json:"public_keys_dir_path"`
}

var config *Config

// LoadConfig loads the configuration from a file or creates a new one if not present.
func LoadConfig() (*Config, error) {
	execDir, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to determine executable path: %w", err)
	}
	configPath := filepath.Join(filepath.Dir(execDir), "config.json")

	// Check if the config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// If not, create a new config file
		config, err = createConfig(configPath)
		if err != nil {
			return nil, err
		}
	} else {
		// Load the config from the existing file
		file, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		config = &Config{}
		if err := json.Unmarshal(file, config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
		}

		// FIX
		// Validate the loaded configuration
		// if err := validateConfig(config); err != nil {
		// 	return nil, err
		// }
	}

	return config, nil
}

// validateConfig checks if all required fields in the configuration are present and non-empty
func validateConfig(cfg *Config) error {
	if cfg.BucketName == "" {
		return fmt.Errorf("missing or empty bucket name in configuration")
	}
	if cfg.ManifestFilePath == "" {
		return fmt.Errorf("missing or empty manifest file path in configuration")
	}
	if cfg.S3Endpoint == "" {
		return fmt.Errorf("missing or empty S3 endpoint in configuration")
	}
	if cfg.APIEndpoint == "" {
		return fmt.Errorf("missing or empty API endpoint in configuration")
	}
	if cfg.Region == "" {
		return fmt.Errorf("missing or empty region in configuration")
	}
	if cfg.LogFilePath == "" {
		return fmt.Errorf("missing or empty log file path in configuration")
	}
	if cfg.PublicKeysDirPath == "" {
		return fmt.Errorf("missing or empty public keys directory path in configuration")
	}
	return nil
}

// createConfig creates a new config file based on user input
func createConfig(path string) (*Config, error) {
	logger := utils.GetLogger()
	logger.Info("Creating new configuration file")

	apiEndpoint, err := utils.UnsecurePrompt("Enter API Endpoint: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read API endpoint: %w", err)
	}

	s3Endpoint, err := utils.UnsecurePrompt("Enter S3 Endpoint: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 endpoint: %w", err)
	}

	region, err := utils.UnsecurePrompt("Enter Region: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read region: %w", err)
	}

	bucketName, err := utils.UnsecurePrompt("Enter S3 Bucket Name: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read bucket name: %w", err)
	}

	manifestFilePath, err := utils.UnsecurePrompt("Enter manifest file path: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file path: %w", err)
	}

	logFilePath, err := utils.UnsecurePrompt("Enter log file path: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read log file path: %w", err)
	}

	publicKeysDirPath, err := utils.UnsecurePrompt("Enter the directory path for storing public keys: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read public keys directory path: %w", err)
	}

	newConfig := &Config{
		BucketName:        bucketName,
		ManifestFilePath:  manifestFilePath,
		S3Endpoint:        s3Endpoint,
		APIEndpoint:       apiEndpoint,
		Region:            region,
		LogFilePath:       logFilePath,
		PublicKeysDirPath: publicKeysDirPath,
	}

	fileData, err := json.MarshalIndent(newConfig, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, fileData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Configuration file created successfully")
	return newConfig, nil
}

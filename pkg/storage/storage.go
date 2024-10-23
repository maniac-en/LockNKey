package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/maniac-en/locknkey/pkg/authentication"
	cfg "github.com/maniac-en/locknkey/pkg/config"
	"github.com/maniac-en/locknkey/pkg/encryption"
	"github.com/maniac-en/locknkey/pkg/manifest"
	"github.com/maniac-en/locknkey/pkg/utils"
)

// S3Client wraps the S3 client for convenience
type S3Client struct {
	client *s3.Client
	cfg    *cfg.Config
}

var s3Client *S3Client

// FetchObject fetches an object from the S3 bucket using ETag for consistency
func (s *S3Client) FetchObject(objectKey string) ([]byte, string, error) {
	logger := utils.GetLogger()
	logger.Debug("Fetching object", "key", objectKey)

	output, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.BucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch object: %w", err)
	}
	defer output.Body.Close()

	data, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read object data: %w", err)
	}

	eTag := aws.ToString(output.ETag)
	logger.Debug("Object fetched successfully", "ETag", eTag)

	return data, eTag, nil
}

// InitializeManifest scans the S3 bucket and populates the manifest structure
// with files and directories
func (s *S3Client) InitializeManifest() error {
	logger := utils.GetLogger()
	logger.Debug("Initializing manifest with current bucket contents")

	manifestObj := &manifest.Manifest{
		Users: make(map[string]string),
		BucketContents: manifest.BucketStructure{
			Root: &manifest.BucketDirectory{},
		},
	}

	// List all objects in the bucket to populate the manifest
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.BucketName),
	}

	paginator := s3.NewListObjectsV2Paginator(s.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			logger.Error("Failed to list objects in bucket", "error", err)
			return fmt.Errorf("failed to list objects in bucket: %w", err)
		}

		for _, obj := range page.Contents {
			objectKey := *obj.Key
			objectPath := SplitPath(objectKey)

			// Add each object to the manifest structure
			bucketObject := manifest.BucketObject{
				ObjectKey: objectKey,
				IsLocked:  false,
			}
			manifestObj.BucketContents.Root.AddFile(bucketObject, objectPath)
		}
	}

	// Marshal and encrypt the manifest before uploading
	data, err := manifest.MarshalManifest(manifestObj)
	if err != nil {
		logger.Error("Failed to marshal manifest", "error", err)
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	encryptedData, err := manifest.EncryptManifest(data)
	if err != nil {
		logger.Error("Failed to encrypt manifest", "error", err)
		return fmt.Errorf("failed to encrypt manifest: %w", err)
	}

	// Use a direct put operation without ETag locking for the initial upload
	_, err = s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.cfg.BucketName),
		Key:    aws.String(s.cfg.ManifestFilePath),
		Body:   bytes.NewReader(encryptedData),
	})
	if err != nil {
		logger.Error("Failed to upload initial manifest", "error", err)
		return fmt.Errorf("failed to upload initial manifest: %w", err)
	}

	logger.Info("Manifest initialized successfully")
	return nil
}

func (s *S3Client) FetchManifest() (*manifest.Manifest, string, error) {
	logger := utils.GetLogger()
	logger.Debug("Fetching and decrypting manifest")

	data, eTag, err := s.FetchObject(s.cfg.ManifestFilePath)
	if err != nil {
		logger.Error(err.Error())
		return nil, "", fmt.Errorf(err.Error())
	}

	decryptedData, err := manifest.DecryptManifest(data)
	if err != nil {
		logger.Error("Failed to decrypt manifest", "error", err)
		return nil, "", fmt.Errorf("failed to decrypt manifest: %w", err)
	}

	manifestObj := &manifest.Manifest{}
	if err := manifest.UnmarshalManifest(decryptedData, manifestObj); err != nil {
		logger.Error("Failed to unmarshal manifest", "error", err)
		return nil, "", fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if err := manifest.ValidateManifest(manifestObj); err != nil {
		logger.Error("Manifest validation failed", "error", err)
		return nil, "", fmt.Errorf("manifest validation failed: %w", err)
	}

	logger.Info("Manifest fetched and decrypted successfully", "ETag", eTag)
	return manifestObj, eTag, nil
}

func (s *S3Client) UpdateManifest(manifestObj *manifest.Manifest, oldETag string) error {
	logger := utils.GetLogger()
	logger.Debug("Updating manifest with ETag-based locking")

	// Marshal and encrypt the manifest
	data, err := manifest.MarshalManifest(manifestObj)
	if err != nil {
		logger.Error("Failed to marshal manifest", "error", err)
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	encryptedData, err := manifest.EncryptManifest(data)
	if err != nil {
		logger.Error("Failed to encrypt manifest", "error", err)
		return fmt.Errorf("failed to encrypt manifest: %w", err)
	}

	// Attempt to update the manifest with the ETag for validation
	err = s.PutObject(s.cfg.ManifestFilePath, encryptedData, oldETag)
	if err != nil {
		logger.Error("Failed to update manifest with ETag", "error", err)
		return fmt.Errorf("failed to update manifest with ETag: %w", err)
	}

	logger.Info("Manifest updated successfully with ETag verification")
	return nil
}

// UploadAndUpdateManifest uploads an object and then updates the manifest accordingly
func (s *S3Client) UploadAndUpdateManifest(objectKey string, data []byte, eTag string) error {
	logger := utils.GetLogger()
	logger.Debug("Starting upload and manifest update", "key", objectKey)

	// Step 1: Upload the object
	err := s.PutObject(objectKey, data, eTag)
	if err != nil {
		return fmt.Errorf("failed to upload object: %w", err)
	}

	// Step 2: Fetch and decrypt the manifest file
	manifestObj, manifestETag, err := s.FetchManifest()
	if err != nil {
		logger.Error("Failed to fetch manifest", "error", err)
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}

	// Step 3: Get all user's public keys
	userData, err := s.FetchAllPublicKeys()
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	// Step 4: Update the manifest object
	currentUser, err := authentication.GetCurrentUser(userData)
	if err != nil {
		logger.Error("Failed to identify the current user", "error", err)
		return fmt.Errorf("failed to identify current user: %w", err)
	}

	objectStatus := manifest.BucketObject{
		ObjectKey: objectKey,
		IsLocked:  true,
		LockedBy:  currentUser,
	}

	// Assuming the object path is split into parts (e.g., folders/subfolders/filename)
	objectPath := SplitPath(objectKey)
	manifestObj.UpdateBucketObject(objectPath, objectStatus)

	// Step 4: Encrypt and upload the updated manifest
	err = s.UpdateManifest(manifestObj, manifestETag)
	if err != nil {
		logger.Error("Failed to update manifest", "error", err)
		return fmt.Errorf("failed to update manifest: %w", err)
	}

	logger.Info("Object uploaded and manifest updated successfully", "key", objectKey)
	return nil
}

func (s *S3Client) RemoveObjectFromManifest(objectKey string) error {
	logger := utils.GetLogger()
	logger.Debug("Removing object from manifest", "key", objectKey)

	manifestObj, manifestETag, err := s.FetchManifest()
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}

	objectPath := SplitPath(objectKey)
	manifestObj.BucketContents.Root.RemoveFile(objectPath)

	if err := s.UpdateManifest(manifestObj, manifestETag); err != nil {
		return fmt.Errorf("failed to update manifest: %w", err)
	}

	logger.Info("Object removed from manifest successfully", "key", objectKey)
	return nil
}

// FetchAllPublicKeys fetches all users and their associated public keys based on the manifest
func (s *S3Client) FetchAllPublicKeys() (*encryption.UserPublicKeyList, error) {
	logger := utils.GetLogger()
	logger.Debug("Fetching all public keys from manifest")

	// Fetch and decrypt the manifest file
	manifestObj, _, err := s.FetchManifest()
	if err != nil {
		logger.Error("Failed to fetch manifest", "error", err)
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	userPublicKeyList := &encryption.UserPublicKeyList{}

	// Iterate over users in the manifest
	for username, publicKeyLocation := range manifestObj.Users {
		// Fetch the public key from object storage using the S3 client
		publicKeyData, _, err := s.FetchObject(publicKeyLocation)
		if err != nil {
			logger.Error("Failed to fetch public key for user", "username", username, "error", err)
			continue
		}

		// Add the user and public key to the list
		userPublicKey := encryption.UserPublicKey{
			Username:  username,
			PublicKey: publicKeyData,
		}
		userPublicKeyList.Users = append(userPublicKeyList.Users, userPublicKey)
		logger.Debug("Public key added for user", "username", username)
	}

	if len(userPublicKeyList.Users) == 0 {
		logger.Warn("No public keys found in the manifest")
		return nil, fmt.Errorf("no public keys found in the manifest")
	}

	logger.Info("Successfully fetched all public keys from manifest")
	return userPublicKeyList, nil
}

// PutObject uploads an object to the S3 bucket with ETag-based locking
func (s *S3Client) PutObject(objectKey string, data []byte, eTag string) error {
	logger := utils.GetLogger()
	logger.Debug("Uploading object with ETag locking", "key", objectKey)

	// First, upload the data as a new object with a temporary key
	tempKey := objectKey + ".tmp"
	_, err := s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.cfg.BucketName),
		Key:    aws.String(tempKey),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("failed to upload temporary object: %w", err)
	}

	// Attempt to copy the temporary object to the target key with ETag-based locking
	_, err = s.client.CopyObject(context.TODO(), &s3.CopyObjectInput{
		Bucket:            aws.String(s.cfg.BucketName),
		Key:               aws.String(objectKey),
		CopySource:        aws.String(fmt.Sprintf("%s/%s", s.cfg.BucketName, tempKey)),
		CopySourceIfMatch: aws.String(eTag),
	})
	if err != nil {
		logger.Warn("ETag mismatch detected during copy operation", "key", objectKey)

		// Refetch and resolve conflict
		serverData, serverETag, fetchErr := s.FetchObject(objectKey)
		if fetchErr != nil {
			return fmt.Errorf("failed to fetch the latest version of the object for conflict resolution: %w", fetchErr)
		}

		manifestObj, _, err := s.FetchManifest()
		if err != nil {
			logger.Error("Failed to fetch manifest", "error", err)
			return fmt.Errorf("failed to fetch manifest: %w", err)
		}

		// Conflict resolution logic based on your business rules (e.g., merge or replace)
		resolvedData, resolveErr := resolveConflict(manifestObj, objectKey, serverData, data)
		if resolveErr != nil {
			return fmt.Errorf("conflict resolution failed: %w", resolveErr)
		}

		// Retry uploading with the resolved data and latest ETag
		return s.PutObject(objectKey, resolvedData, serverETag)
	}

	// Clean up the temporary object
	_, err = s.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(s.cfg.BucketName),
		Key:    aws.String(tempKey),
	})
	if err != nil {
		return fmt.Errorf("failed to delete temporary object: %w", err)
	}

	logger.Info("Object uploaded successfully with ETag verification", "key", objectKey)
	return nil
}

func (s *S3Client) RegisterUser(publicKey []byte, username string) error {
	logger := utils.GetLogger()
	logger.Debug("Registering new user", "username", username)

	// Fetch and decrypt the manifest file
	manifestObj, manifestETag, err := s.FetchManifest()
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}

	// Upload user's publicKey to cloud
	publicKeyPath := s3Client.cfg.PublicKeysDirPath + "/" + username + "_pub.key"
	_, err = s3Client.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.cfg.BucketName),
		Key:    aws.String(publicKeyPath),
		Body:   bytes.NewReader(publicKey),
	})
	if err != nil {
		logger.Error("Failed to upload initial public key on user registration", "username", username, "error", err)
		return fmt.Errorf("Failed to upload initial public key on user registration for %s: %w", username, err)
	}

	// Update the users map in the manifest
	manifestObj.Users[username] = publicKeyPath

	// Update the manifest file
	if err := s.UpdateManifest(manifestObj, manifestETag); err != nil {
		return fmt.Errorf("failed to update manifest: %w", err)
	}

	logger.Info("User registered successfully", "username", username)
	return nil
}

// InitializeS3Client initializes the S3 client
func InitializeS3Client(cfg *cfg.Config, username string) error {
	logger := utils.GetLogger()
	logger.Info("Initializing S3 Client")

	// Ensure s3Client is allocated memory
	if s3Client == nil {
		s3Client = &S3Client{}
	}

	accessKey, err := encryption.RetrieveAndDecryptToken("object_storage_access_key_" + username)
	if err != nil {
		logger.Error("Failed to retrieve access key", "error", err)
		return err
	}

	secretKey, err := encryption.RetrieveAndDecryptToken("object_storage_secret_key_" + username)
	if err != nil {
		logger.Error("Failed to retrieve secret key", "error", err)
		return err
	}

	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(
			credentials.StaticCredentialsProvider{
				Value: aws.Credentials{
					AccessKeyID:     accessKey,
					SecretAccessKey: secretKey,
				},
			},
		),
		config.WithEndpointResolver(aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			if service == s3.ServiceID && region == cfg.Region {
				return aws.Endpoint{
					URL:           cfg.S3Endpoint,
					SigningRegion: region,
				}, nil
			}
			return aws.Endpoint{}, fmt.Errorf("unknown endpoint requested")
		})),
	)
	if err != nil {
		logger.Error("Failed to load AWS configuration", "error", err)
		return fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	s3Client.client = s3.NewFromConfig(awsCfg)
	s3Client.cfg = cfg
	logger.Info("S3 client initialized successfully")

	return nil
}

// GetS3Client returns the s3 client instance if initialized, otherwise exits
func GetS3Client() *S3Client {
	if s3Client == nil {
		fmt.Println("S3 Client is not initialized. Please call InitializeS3Client first.")
		os.Exit(1)
	}
	return s3Client
}

// resolveConflict handles conflicts when there's an ETag mismatch.
// It checks the lock status of the object and decides the appropriate action.
func resolveConflict(manifestObj *manifest.Manifest, objectKey string, existingData, newData []byte) ([]byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Resolving conflict for object", "key", objectKey)

	// Determine the path components for the object
	pathComponents := SplitPath(objectKey)

	// Check if the object is locked and by whom
	isLocked, lockedBy := manifestObj.BucketContents.Root.CheckObjectLock(pathComponents)
	logger.Debug("Object lock status", "isLocked", isLocked, "lockedBy", lockedBy)

	if !isLocked {
		logger.Warn("Object is not locked; discarding local changes", "key", objectKey)
		// Discard the local changes and use the server version
		return existingData, nil
	}

	userData, err := s3Client.FetchAllPublicKeys()
	if err != nil {
		logger.Error(err.Error())
		return nil, fmt.Errorf(err.Error())
	}

	currentUser, err := authentication.GetCurrentUser(userData)
	if err != nil {
		logger.Error("Failed to determine current user", "error", err)
		return nil, fmt.Errorf("failed to determine current user: %w", err)
	}

	if lockedBy == currentUser {
		logger.Warn("Object is locked by the current user; prompting for resolution", "key", objectKey)
		// The object is locked by the current user; prompt for resolution
		fmt.Println("A conflict was detected for the object:", objectKey)
		fmt.Println("Choose how to resolve the conflict:")
		fmt.Println("1. Keep the server version")
		fmt.Println("2. Overwrite with your local version")

		var choice int
		_, err := fmt.Scan(&choice)
		if err != nil {
			logger.Error("Failed to read user choice", "error", err)
			return nil, fmt.Errorf("failed to read user choice: %w", err)
		}

		switch choice {
		case 1:
			logger.Info("User chose to keep the server version", "key", objectKey)
			return existingData, nil
		case 2:
			logger.Info("User chose to overwrite with local version", "key", objectKey)
			return newData, nil
		default:
			logger.Warn("Invalid choice; defaulting to keeping the server version", "key", objectKey)
			return existingData, nil
		}
	} else {
		logger.Warn("Object is locked by another user; discarding local changes", "key", objectKey)
		// The object is locked by another user; discard local changes
		return existingData, nil
	}
}

// SplitPath splits an object key into path components.
func SplitPath(objectKey string) []string {
	parts := bytes.Split([]byte(objectKey), []byte("/"))
	result := make([]string, len(parts))
	for i, part := range parts {
		result[i] = string(part)
	}
	return result
}

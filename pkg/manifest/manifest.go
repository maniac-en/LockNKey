package manifest

import (
	"encoding/json"
	"fmt"

	"github.com/maniac-en/locknkey/pkg/utils"
)

// BucketObject represents a file in the bucket
type BucketObject struct {
	IsLocked  bool   `json:"is_locked"`
	LockedBy  string `json:"locked_by,omitempty"`
	ObjectKey string `json:"object_key"`
}

// BucketDirectory represents a directory in the bucket and can contain nested
// directories or files
type BucketDirectory struct {
	SubDirectories map[string]*BucketDirectory `json:"subdirectories"`
	Files          []BucketObject              `json:"files"`
}

// BucketStructure represents the entire structure of the bucket
type BucketStructure struct {
	Root *BucketDirectory `json:"root"`
}

// Manifest structure representing the users and their associated public keys
type Manifest struct {
	Users          map[string]string `json:"users"`
	BucketContents BucketStructure   `json:"bucket_contents"`
}

// AddFile adds or updates a file in the directory structure
func (dir *BucketDirectory) AddFile(file BucketObject, path []string) {
	logger := utils.GetLogger()

	if len(path) == 0 {
		logger.Debug("Adding file to directory", "file", file.ObjectKey)
		dir.Files = append(dir.Files, file)
		return
	}

	subDirName := path[0]
	if dir.SubDirectories == nil {
		dir.SubDirectories = make(map[string]*BucketDirectory)
	}

	if _, exists := dir.SubDirectories[subDirName]; !exists {
		logger.Debug("Creating subdirectory", "name", subDirName)
		dir.SubDirectories[subDirName] = &BucketDirectory{}
	}

	dir.SubDirectories[subDirName].AddFile(file, path[1:])
}

// CheckObjectLock recursively checks if a file/directory is locked and by whom
func (dir *BucketDirectory) CheckObjectLock(path []string) (bool, string) {
	logger := utils.GetLogger()

	if len(path) == 0 {
		logger.Debug("No more elements in path; returning no lock")
		return false, ""
	}

	subDirName := path[0]
	if subDir, exists := dir.SubDirectories[subDirName]; exists {
		logger.Debug("Checking lock status in subdirectory", "subDirName", subDirName)
		return subDir.CheckObjectLock(path[1:])
	}

	// If it's the last element in the path and matches a file, check the file lock status
	if len(path) == 1 {
		for _, file := range dir.Files {
			if file.ObjectKey == path[0] {
				logger.Debug("File found; returning lock status", "file", file.ObjectKey, "isLocked", file.IsLocked)
				return file.IsLocked, file.LockedBy
			}
		}
	}

	logger.Debug("Object not found; returning no lock")
	return false, ""
}

func (dir *BucketDirectory) RemoveFile(path []string) {
	logger := utils.GetLogger()

	if len(path) == 0 {
		return
	}

	if len(path) == 1 {
		// Remove the file from this directory's files
		for i, file := range dir.Files {
			if file.ObjectKey == path[0] {
				logger.Debug("Removing file", "file", file.ObjectKey)
				dir.Files = append(dir.Files[:i], dir.Files[i+1:]...)
				return
			}
		}
	} else {
		subDirName := path[0]
		if subDir, exists := dir.SubDirectories[subDirName]; exists {
			subDir.RemoveFile(path[1:])
		}
	}
}

// UpdateBucketObject updates the status of a file in the manifest
func (m *Manifest) UpdateBucketObject(path []string, object BucketObject) {
	logger := utils.GetLogger()
	logger.Debug("Updating bucket object", "object", object.ObjectKey)

	if m.BucketContents.Root == nil {
		logger.Debug("Creating root directory for the bucket structure")
		m.BucketContents.Root = &BucketDirectory{}
	}

	m.BucketContents.Root.AddFile(object, path)
}

// DecryptManifest decrypts the manifest data
func DecryptManifest(data []byte) ([]byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Decrypting manifest data")

	// Placeholder logic for decryption
	return data, nil
}

// EncryptManifest encrypts the manifest data
func EncryptManifest(data []byte) ([]byte, error) {
	logger := utils.GetLogger()
	logger.Debug("Encrypting manifest data")

	// Placeholder logic for encryption
	return data, nil
}

// UnmarshalManifest unmarshals the manifest data
func UnmarshalManifest(data []byte, manifest *Manifest) error {
	return json.Unmarshal(data, manifest)
}

// MarshalManifest marshals the manifest into JSON
func MarshalManifest(manifest *Manifest) ([]byte, error) {
	return json.Marshal(manifest)
}

func ValidateManifest(manifest *Manifest) error {
	if manifest.Users == nil {
		return fmt.Errorf("manifest validation failed: users field is missing")
	}
	if manifest.BucketContents.Root == nil {
		return fmt.Errorf("manifest validation failed: bucket structure root is missing")
	}

	return nil
}

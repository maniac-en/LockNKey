package utils

import (
	"crypto/sha256"
	"fmt"

	"github.com/denisbrodbeck/machineid"
	"golang.org/x/crypto/pbkdf2"
)

// getHashedMachineID retrieves a unique hashed hardware ID for the system
func GetHashedMachineID() (string, error) {
	hashedID, err := machineid.ProtectedID("LockNKey")
	if err != nil {
		return "", fmt.Errorf("failed to get hashed machine ID: %w", err)
	}
	return hashedID, nil
}

// generateSystemBoundKey derives an AES key based on the hashed machine ID
func GenerateSystemBoundKey() ([]byte, error) {
	hashedID, err := GetHashedMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get hashed machine ID: %w", err)
	}

	salt := []byte(hashedID)
	return pbkdf2.Key([]byte(hashedID), salt, 4096, 32, sha256.New), nil
}

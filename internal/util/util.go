package util

import (
	"cloud.google.com/go/compute/metadata"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const (
	keyLength           = 2048
	aadMetadataKey      = "kms-aad"
	kmsKeyIdMetadataKey = "kms-key-id"
)

func GetKeyAAD(keyAAD string) (string, error) {
	var attrNotDefined metadata.NotDefinedError
	// If there is a key id set already, do nothing
	if keyAAD != "" {
		return keyAAD, nil
	}
	// Set KMS key from meta: either special-purpose key or use instanceId
	keyAAD, err := metadata.InstanceAttributeValue(aadMetadataKey)
	if errors.As(err, &attrNotDefined) {
		keyAAD, err = metadata.InstanceID()
		if err != nil {
			return "", err
		}
		return keyAAD, nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot probe metadata for kms-aad: %s", err)
	}
	if keyAAD == "" {
		return "", fmt.Errorf("empty aad context key")
	}
	return keyAAD, nil
}

func GetKMSKeyID(keyID string) (string, error) {
	// If there is a key id set already, do nothing
	if keyID != "" {
		return keyID, nil
	}
	// Set KMS key from meta
	keyID, err := metadata.InstanceAttributeValue(kmsKeyIdMetadataKey)
	if err != nil {
		return "", fmt.Errorf("cannot probe metadata for kms-key-id: %s", err)
	}
	if keyID == "" {
		return "", fmt.Errorf("KMS key ID must be supplied")
	}
	return keyID, nil
}

func generateLUKSKey() ([]byte, error) {
	buf := make([]byte, keyLength)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("unable to generate random key: %s", err)
	}
	return buf, nil
}

// getPlaintextLUKSKey reads plaintext binary key or generate a new one
func GetPlaintextLUKSKey(keyfilePath string) ([]byte, error) {
	var keyBytes []byte
	var err error
	// Keypath not set, generating
	if keyfilePath == "" {
		keyBytes, err = generateLUKSKey()
		if err != nil {
			return nil, err
		}
		return keyBytes, nil
	}
	keyBytes, err = os.ReadFile(keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening key: %s", err)
	}
	return keyBytes, nil
}

func Base64Encode(data []byte) []byte {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst
}

func Base64Decode(encodedData []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(encodedData)))

	readLen, err := base64.StdEncoding.Decode(dst, encodedData)
	if err != nil {
		return nil, fmt.Errorf("key decoding error: %w", err)
	}

	return dst[:readLen], nil
}

func CheckEncryptedKeyAlreadyPresent(keypath string) error {
	// Keypath not set, cannot overwrite what not exists
	if keypath == "" {
		return nil
	}
	// Try stat() on the filepath
	_, err := os.Stat(keypath)
	// File does not exist?
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	// we have stat() data -- which means file does exist.
	if err == nil {
		return fmt.Errorf("encrypted key file already present")
	}
	// There probably was an error, like permission or else -- but we do not care.
	return nil
}

package main

import (
	"cloud.google.com/go/compute/metadata"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"io/fs"
	"log"
	"os"
)

const (
	apiEndpoint         = "api.il.nebius.cloud:443"
	keyLength           = 2048
	aadMetadataKey      = "kms-aad"
	kmsKeyIdMetadataKey = "kms-key-id"
)

type config struct {
	KeyPath          string
	KeyPathEncrypted string
	KMSKeyID         string
	ForceOverwrite   bool
	KeyAAD           string
}

func parseFlags(conf *config) {
	flag.StringVar(
		&conf.KeyPath,
		"key",
		"",
		"Location of key file (input)")
	flag.StringVar(
		&conf.KeyPathEncrypted,
		"encrypted-key",
		"",
		"Location of encrypted key file (output)")
	flag.StringVar(
		&conf.KeyAAD,
		"key-aad",
		"",
		"Additional encryption context for KMS")
	flag.BoolVar(
		&conf.ForceOverwrite,
		"force-key-overwrite",
		false,
		"Forces key overwrite even if the file is already present in the destination")
	flag.StringVar(
		&conf.KMSKeyID,
		"kmsid",
		"",
		"KMS key ID")
	flag.Parse()
}

func getKeyAAD(keyAAD string) (string, error) {
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

func getKMSKey(keyID string) (string, error) {
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
func getPlaintextLUKSKey(keyfilePath string) ([]byte, error) {
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

func base64Encode(data []byte) []byte {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst
}

func checkEncryptedKeyAlreadyPresent(keypath string) error {
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

func main() {
	conf := &config{}
	// Parse flags
	parseFlags(conf)

	// Accidental overwrite of LUKS encryption key may potentially cause total loss of disk data.
	if !conf.ForceOverwrite {
		err := checkEncryptedKeyAlreadyPresent(conf.KeyPathEncrypted)
		if err != nil {
			log.Fatalln(err)
		}
	}

	kmsKeyID, err := getKMSKey(conf.KMSKeyID)
	if err != nil {
		log.Fatal(err)
	}
	keyBytes, err := getPlaintextLUKSKey(conf.KeyPath)
	if err != nil {
		log.Fatal(err)
	}

	aadContext, err := getKeyAAD(conf.KeyAAD)
	if err != nil {
		log.Fatal(err)
	}

	// Request decryption
	ctx := context.Background()
	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Endpoint:    apiEndpoint,
		Credentials: ycsdk.InstanceServiceAccount(),
	})
	if err != nil {
		log.Fatalf("failed to init YC SDK: %s", err)
	}
	response, err := sdk.KMSCrypto().SymmetricCrypto().Encrypt(ctx, &kms.SymmetricEncryptRequest{
		KeyId:      kmsKeyID,
		Plaintext:  keyBytes,
		AadContext: []byte(aadContext),
	})
	if err != nil {
		log.Fatalf("unable to encrypt key: %s", err)
	}
	ciphertextKey := response.Ciphertext
	filePath := conf.KeyPathEncrypted
	if filePath == "" {
		filePath = os.Stdout.Name()
	}
	if err := os.WriteFile(filePath, base64Encode(ciphertextKey), 0); err != nil {
		log.Fatalf("unable to write encrypted key: %s", err)
	}
}

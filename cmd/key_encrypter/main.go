package main

import (
	"cloud.google.com/go/compute/metadata"
	"context"
	"flag"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"log"
	"os"
)

const (
	apiEndpoint      = "api.il.nebius.cloud:443"
	keypath          = "/keyfile.bin"
	encryptedKeypath = keypath + ".enc"
)

type config struct {
	KeyPath          string
	KeyPathEncrypted string
	KMSKeyID         string
}

func parseFlags(conf *config) {
	flag.StringVar(
		&conf.KeyPath,
		"key",
		keypath,
		"Location of key file")
	flag.StringVar(
		&conf.KeyPathEncrypted,
		"encrypted-key",
		encryptedKeypath,
		"Location of encrypted key file")
	flag.StringVar(
		&conf.KMSKeyID,
		"kmsid",
		"",
		"KMS key ID")
	flag.Parse()
	if conf.KMSKeyID == "" {
		log.Fatalf("KMS key ID must be supplied")
	}
}

func main() {
	conf := &config{}
	// Parse flags
	parseFlags(conf)
	// Read plaintext binary
	keyBytes, err := os.ReadFile(conf.KeyPath)
	if err != nil {
		log.Fatalf("error opening key: %s", err)
	}
	// Request decryption
	ctx := context.Background()

	instanceId, err := metadata.InstanceID()
	if err != nil {
		log.Fatalf("unable to get instance ID: %s", err)
	}

	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Endpoint:    apiEndpoint,
		Credentials: ycsdk.InstanceServiceAccount(),
	})
	if err != nil {
		log.Fatalf("failed to init YC SDK: %s", err)
	}
	response, err := sdk.KMSCrypto().SymmetricCrypto().Encrypt(ctx, &kms.SymmetricEncryptRequest{
		KeyId:      conf.KMSKeyID,
		Plaintext:  keyBytes,
		AadContext: []byte(instanceId),
	})
	if err != nil {
		log.Fatalf("unable to encrypt key: %s", err)
	}
	ciphertextKey := response.Ciphertext
	if err := os.WriteFile(conf.KeyPathEncrypted, ciphertextKey, 0); err != nil {
		log.Fatalf("unable to write encrypted key: %s", err)
	}
}

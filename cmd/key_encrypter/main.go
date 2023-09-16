package main

import (
	"context"
	"decrypter/internal/util"
	"flag"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"log"
	"os"
)

const (
	apiEndpoint = "api.il.nebius.cloud:443"
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

func main() {
	conf := &config{}
	// Parse flags
	parseFlags(conf)

	// Accidental overwrite of LUKS encryption key may potentially cause total loss of disk data.
	if !conf.ForceOverwrite {
		err := util.CheckEncryptedKeyAlreadyPresent(conf.KeyPathEncrypted)
		if err != nil {
			log.Fatalln(err)
		}
	}

	kmsKeyID, err := util.GetKMSKeyID(conf.KMSKeyID)
	if err != nil {
		log.Fatal(err)
	}
	keyBytes, err := util.GetPlaintextLUKSKey(conf.KeyPath)
	if err != nil {
		log.Fatal(err)
	}

	aadContext, err := util.GetKeyAAD(conf.KeyAAD)
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
	if err := os.WriteFile(filePath, util.Base64Encode(ciphertextKey), 0); err != nil {
		log.Fatalf("unable to write encrypted key: %s", err)
	}
}

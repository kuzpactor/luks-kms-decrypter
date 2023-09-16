package main

import (
	"context"
	"decrypter/internal/util"
	"flag"
	"log"
	"os"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
)

const apiEndpoint = "api.il.nebius.cloud:443"

type config struct {
	KeyPath  string
	KMSKeyID string
}

func parseFlags(conf *config) {
	flag.StringVar(
		&conf.KeyPath,
		"key",
		"/keyfile.enc.bin",
		"Location of encrypted key file")
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

	// Read encrypted binary
	cipherKeyBytesB64, err := os.ReadFile(conf.KeyPath)
	if err != nil {
		log.Fatalf("error opening key: %s", err)
	}

	cipherKeyBytes, err := util.Base64Decode(cipherKeyBytesB64)
	if err != nil {
		log.Fatal(err)
	}

	kmsKeyID, err := util.GetKMSKeyID(conf.KMSKeyID)
	if err != nil {
		log.Fatal(err)
	}

	aadContext, err := util.GetKeyAAD("")
	if err != nil {
		log.Fatalf("unable to get instance ID: %s", err)
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

	response, err := sdk.KMSCrypto().SymmetricCrypto().Decrypt(ctx, &kms.SymmetricDecryptRequest{
		KeyId:      kmsKeyID,
		Ciphertext: cipherKeyBytes,
		AadContext: []byte(aadContext),
	})
	if err != nil {
		log.Fatalf("unable to decrypt key: %s", err)
	}

	_, _ = os.Stdout.Write(response.Plaintext)
}

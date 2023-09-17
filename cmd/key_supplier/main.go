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
	log.Print("resolving arguments...")
	parseFlags(conf)
	log.Printf("args: %#v", conf)

	// Read encrypted binary
	log.Printf("reading encrypted key at '%s'...", conf.KeyPath)
	cipherKeyBytesB64, err := os.ReadFile(conf.KeyPath)
	if err != nil {
		log.Fatalf("error opening key: %s", err)
	}

	cipherKeyBytes, err := util.Base64Decode(cipherKeyBytesB64)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("key at '%s' read OK", conf.KeyPath)

	log.Println("resolving KMS key ID...")
	kmsKeyID, err := util.GetKMSKeyID(conf.KMSKeyID)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("KMS key ID: %s", kmsKeyID)

	log.Println("resolving AAD context...")
	aadContext, err := util.GetKeyAAD("")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("AAD context read OK, %d bytes", len(aadContext))

	// Request decryption
	log.Println("init YC API...")
	ctx := context.Background()
	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Endpoint:    apiEndpoint,
		Credentials: ycsdk.InstanceServiceAccount(),
	})
	if err != nil {
		log.Fatalf("failed to init YC SDK: %s", err)
	}

	log.Println("calling KMS API...")
	response, err := sdk.KMSCrypto().SymmetricCrypto().Decrypt(ctx, &kms.SymmetricDecryptRequest{
		KeyId:      kmsKeyID,
		Ciphertext: cipherKeyBytes,
		AadContext: []byte(aadContext),
	})
	if err != nil {
		log.Fatalf("unable to decrypt key: %s", err)
	}
	log.Printf("key decryption successfull, writing %d bytes to stdout", len(response.Plaintext))

	_, _ = os.Stdout.Write(response.Plaintext)
}

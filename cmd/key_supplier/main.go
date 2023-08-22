package main

import (
	"cloud.google.com/go/compute/metadata"
	"context"
	"flag"
	"fmt"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"log"
	"net"
	"os"
	"syscall"
)

const apiEndpoint = "api.il.nebius.cloud:443"

type config struct {
	SocketPath string
	Foreground bool
	KeyPath    string
	KMSKeyID   string
}

func daemonize() error {
	ret, _, errno := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("unable to fork, errno %d", errno)
	}
	switch ret {
	case 0:
		// Child
		break
	default:
		// Parent
		os.Exit(0)
	}
	pid, err := syscall.Setsid()
	if pid == -1 {
		return fmt.Errorf("setsid() failed: %s", err)
	}
	err = os.Chdir("/")
	if err != nil {
		return fmt.Errorf("unable to chdir(): %s", err)
	}
	devnull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("unable to open devnull: %s", err)
	}
	fd := devnull.Fd()
	syscall.Dup2(int(fd), int(os.Stdin.Fd()))
	syscall.Dup2(int(fd), int(os.Stdout.Fd()))
	syscall.Dup2(int(fd), int(os.Stderr.Fd()))
	return nil
}

func parseFlags(conf *config) {
	flag.BoolVar(
		&conf.Foreground,
		"foreground",
		false,
		"Do not daemonize, stay on foreground")
	flag.StringVar(
		&conf.SocketPath,
		"socket",
		"/tmp/key.socket",
		"Location of the socket that will be used for communication with decryption utility")
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
	if conf.KMSKeyID == "" {
		log.Fatalf("KMS key ID must be supplied")
	}
}

func main() {
	conf := &config{}
	// Parse flags
	parseFlags(conf)
	// Read encrypted binary
	cipherKeyBytes, err := os.ReadFile(conf.KeyPath)
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
	response, err := sdk.KMSCrypto().SymmetricCrypto().Decrypt(ctx, &kms.SymmetricDecryptRequest{
		KeyId:      conf.KMSKeyID,
		Ciphertext: cipherKeyBytes,
		AadContext: []byte(instanceId),
	})
	if err != nil {
		log.Fatalf("unable to decrypt key: %s", err)
	}
	plaintextKey := response.Plaintext
	if err := daemonize(); err != nil {
		log.Fatal(err)
	}
	// Open socket
	socket, err := net.Listen("unix", conf.SocketPath)
	if err != nil {
		log.Fatalf("unable to open socket: %s", err)
	}
	defer cleanup(socket, conf.SocketPath)
	// Daemonize (Parent exits normally at this time)
	for {
		// Start accepting connections
		conn, err := socket.Accept()
		if err != nil {
			log.Fatal(err)
		}

		// Handle the connection in a separate goroutine.
		go func(conn net.Conn) {
			defer conn.Close()
			// Write decrypted key when there is connection
			_, err = conn.Write(plaintextKey)
			if err != nil {
				log.Fatal(err)
			}
			os.Exit(0)
		}(conn)
	}
	// When connection is done, exit normally
}

func cleanup(sock net.Listener, path string) {
	sock.Close()
	os.Remove(path)
}

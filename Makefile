build_dir = build

clean:
	rm -fr $(build_dir)

build:
	GOOS=linux GOARCH=amd64 go build -o $(build_dir)/bin/key_supplier cmd/key_supplier/main.go
	GOOS=linux GOARCH=amd64 go build -o $(build_dir)/bin/key_encrypter cmd/key_encrypter/main.go
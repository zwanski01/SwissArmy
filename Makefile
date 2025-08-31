.PHONY: build clean test release install

BINARY_NAME=swissarmygo
VERSION=$(shell git describe --tags --always --dirty)

build:
	go build -o $(BINARY_NAME) -ldflags "-X main.version=$(VERSION)" main.go

clean:
	rm -f $(BINARY_NAME)
	rm -rf bin/

test:
	go test -v ./...

release:
	GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY_NAME)-linux-amd64 main.go
	GOOS=windows GOARCH=amd64 go build -o bin/$(BINARY_NAME)-windows-amd64.exe main.go
	GOOS=darwin GOARCH=amd64 go build -o bin/$(BINARY_NAME)-darwin-amd64 main.go

install: build
	sudo mv $(BINARY_NAME) /usr/local/bin/

deps:
	go mod download
	go mod verify

lint:
	golangci-lint run

.PHONY: coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

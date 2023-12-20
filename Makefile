GOCMD=go
SEC=gosec
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean

.PHONY: all build clean test

all: build

build:
	$(GOCMD) get "golang.org/x/crypto/ssh"
	$(GOBUILD) go-ssh-cracker.go

test:
	$(GOCMD) get "golang.org/x/crypto/ssh"
	$(GOCMD) test -v

sec:
	$(GOCMD) install github.com/securego/gosec/v2/cmd/gosec@latest
	$(SEC) ./

clean:
	$(GOCLEAN)

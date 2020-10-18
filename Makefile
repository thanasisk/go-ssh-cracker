GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean

.PHONY: all build clean test

all: build

build:
	$(GOCMD) get "golang.org/x/crypto/ssh"
	$(GOBUILD) go-ssh-cracker.go

test:
	$(GOCMD) get "golang.org/x/crypto/ssh"
	$(GOCMD) test

clean:
	$(GOCLEAN)

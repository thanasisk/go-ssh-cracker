GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean

.PHONY: all build clean

all: build

build:
	$(GOCMD) get "golang.org/x/crypto/ssh"
	$(GOBUILD) go-ssh-cracker.go

clean:
	$(GOCLEAN)

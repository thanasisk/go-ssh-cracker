GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean

.PHONY: all build clean

all: build

build:
	$(GOBUILD) delaporter.go

clean:
	$(GOCLEAN)

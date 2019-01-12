# Go parameters

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean

# Build environment
BUILD_DIR=bins
BUILD_OPTIONS=-ldflags="-s -w"
SRC_DIR=crypter
ARCH=386

# Files to build
EXECUTABLES=encrypt decrypt decrypt-offline

all: clean server windows linux

clean:
	$(GOCLEAN)
	rm -f $(BUILD_DIR)/*

server:
	$(GOBUILD) decrypt_key.go
	$(GOBUILD) server.go

windows:
	@$(foreach exec, $(EXECUTABLES), GOOS=windows GOARCH=$(ARCH) $(GOBUILD) $(BUILD_OPTIONS) -o $(BUILD_DIR)/$(exec)-windows-$(ARCH) $(SRC_DIR)/$(exec).go;)

linux:
	@$(foreach exec, $(EXECUTABLES), GOOS=linux GOARCH=$(ARCH) $(GOBUILD) $(BUILD_OPTIONS) -o $(BUILD_DIR)/$(exec)-linux-$(ARCH) $(SRC_DIR)/$(exec).go;)

.PHONY: clean server windows linux

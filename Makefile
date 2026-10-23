# Copyright The Linux Foundation and its contributors.
# SPDX-License-Identifier: MIT

.PHONY: docker-build ko-build-local megalinter

IMAGE_NAME ?= linuxfoundation/auth0-cas-server-go

GIT_HASH = $(shell git describe --dirty --always)

# The default target creates a local build of auth0-cas-server-go.
bin/auth0-cas-server-go: *.go go.mod go.sum
	@mkdir -p bin
	go build -o bin/auth0-cas-server-go github.com/linuxfoundation/auth0-cas-server-go

all: bin/auth0-cas-server-go docker-build

# Run MegaLinter locally via Docker (matches CI Go flavor at v10.1.0).
# Keep this digest in sync with .github/workflows/mega-linter.yml.
MEGALINTER_IMAGE := ghcr.io/oxsecurity/megalinter-go@sha256:42e091a4bcbe9141fe420c2520ed7addf75ae60a0c9d42e3df1278eef1c90a88  # v10.1.0

megalinter:
	docker pull $(MEGALINTER_IMAGE)
	docker run --rm --platform linux/amd64 -e GOTOOLCHAIN=auto -v '$(CURDIR):/tmp/lint:rw' $(MEGALINTER_IMAGE)

test:
	@echo "No tests to run ... would you like to 'make megalinter'?"

# Build and label a local Docker container of auth0-cas-server-go.
docker-build:
	docker build -t $(IMAGE_NAME):$(GIT_HASH) -t $(IMAGE_NAME):latest .

ko-build-local: bin/auth0-cas-server-go
	ko build --local --tags $(GIT_HASH),latest --platform linux/amd64,linux/arm64 --sbom-dir sbom github.com/linuxfoundation/auth0-cas-server-go

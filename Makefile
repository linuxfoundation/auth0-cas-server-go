# Copyright The Linux Foundation and its contributors.
# SPDX-License-Identifier: MIT

.PHONY: docker-build ko-build-local

IMAGE_NAME ?= linuxfoundation/auth0-cas-server-go

GIT_HASH = $(shell git describe --dirty --always)

# The default target creates a local build of auth0-cas-server-go.
bin/auth0-cas-server-go: *.go go.mod go.sum
	@mkdir -p bin
	go build -o bin/auth0-cas-server-go github.com/linuxfoundation/auth0-cas-server-go

all: bin/auth0-cas-server-go docker-build

lint:
	docker pull --platform linux/amd64 oxsecurity/megalinter-go:v8
	docker run --rm --platform linux/amd64 -v '$(CURDIR):/tmp/lint:rw' oxsecurity/megalinter-go:v8

test:
	@echo "No tests to run ... would you like to 'make lint'?"

# Build and label a local Docker container of auth0-cas-server-go.
docker-build:
	docker build -t $(IMAGE_NAME):$(GIT_HASH) -t $(IMAGE_NAME):latest .

ko-build-local: bin/auth0-cas-server-go
	ko build --local --tags $(GIT_HASH),latest --platform linux/amd64,linux/arm64 --sbom-dir sbom github.com/linuxfoundation/auth0-cas-server-go

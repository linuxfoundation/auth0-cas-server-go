# Clone this repo outside $GOPATH (go mod)

.PHONY: docker-build

IMAGE_NAME ?= linuxfoundation/auth0-cas-server-go

GIT_HASH = $(shell git describe --dirty --always)

bin/auth0-cas-server-go: *.go go.mod go.sum
	@mkdir -p bin
	go build -o bin/auth0-cas-server-go gitlab.com/linuxfoundation/auth0/auth0-cas-server-go

docker-build:
	docker build -t $(IMAGE_NAME):$(GIT_HASH) .

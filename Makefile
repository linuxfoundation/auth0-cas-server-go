# Clone this repo outside $GOPATH (go mod)

.PHONY: docker-build

bin/auth0-cas-server-go: *.go go.mod go.sum
	@mkdir -p bin
	go build -o bin/auth0-cas-server-go gitlab.com/linuxfoundation/auth0/auth0-cas-server-go

docker-build:
	docker build -t auth0-cas-server-go .

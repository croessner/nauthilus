OUTPUT := nauthilus/bin/nauthilus
PKG_LIST := $(shell go list ./... | grep -v /vendor/)
GIT_TAG=$(shell git describe --tags --abbrev=0)
GIT_COMMIT=$(shell git rev-parse --short HEAD)

.PHONY: all test race msan build clean

all: build

$(OUTPUT):
	mkdir -p $(dir $(OUTPUT))

test:
	go test -short ${PKG_LIST}

race:
	go test -race -short ${PKG_LIST}

msan:
	go test -msan -short ${PKG_LIST}

build:
	go build -mod=vendor -v -ldflags "-X main.buildTime=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') -X main.version=$(GIT_TAG)-$(GIT_COMMIT)" -o $(OUTPUT) ./server

clean: ## Remove previous build
	[ -x $(OUTPUT) ] && rm -f $(OUTPUT)

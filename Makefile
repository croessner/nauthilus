OUTPUT := nauthilus/bin/nauthilus
CLIENT_OUTPUT := nauthilus/bin/nauthilus-client
PKG_LIST := $(shell go list ./... | grep -v /vendor/)
GIT_TAG=$(shell git describe --tags --abbrev=0)
GIT_COMMIT=$(shell git rev-parse --short HEAD)

export GOEXPERIMENT := greenteagc

.PHONY: all test race msan build build-client clean install uninstall

all: build build-client

$(OUTPUT) $(CLIENT_OUTPUT):
	mkdir -p $(dir $@)

test:
	go test -short ${PKG_LIST}

race:
	go test -race -short ${PKG_LIST}

msan:
	go test -msan -short ${PKG_LIST}

build: $(OUTPUT)
	go build -mod=vendor -trimpath -v -ldflags "-X main.buildTime=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') -X main.version=$(GIT_TAG)-$(GIT_COMMIT)" -o $(OUTPUT) ./server

build-client: $(CLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(CLIENT_OUTPUT) ./client

clean: ## Remove previous build
	[ -x $(OUTPUT) ] && rm -f $(OUTPUT) || true
	[ -x $(CLIENT_OUTPUT) ] && rm -f $(CLIENT_OUTPUT) || true

install: build ## Install nauthilus binary and systemd service
	install -D -m 755 $(OUTPUT) /usr/local/sbin/nauthilus
	install -D -m 644 systemd/nauthilus.service /etc/systemd/system/nauthilus.service
	@echo "Installed nauthilus binary to /usr/local/sbin/nauthilus"
	@echo "Installed systemd service to /etc/systemd/system/nauthilus.service"
	@echo "You may need to run 'systemctl daemon-reload' to use the service"

uninstall: ## Uninstall nauthilus binary and systemd service
	rm -f /usr/local/sbin/nauthilus
	rm -f /etc/systemd/system/nauthilus.service
	@echo "Removed nauthilus binary from /usr/local/sbin/nauthilus"
	@echo "Removed systemd service from /etc/systemd/system/nauthilus.service"
	@echo "You may need to run 'systemctl daemon-reload' to apply changes"

OUTPUT := nauthilus/bin/nauthilus
CLIENT_OUTPUT := nauthilus/bin/nauthilus-client
OIDCTESTCLIENT_OUTPUT := nauthilus/bin/oidctestclient
SAML2TESTCLIENT_OUTPUT := nauthilus/bin/saml2testclient
PKG_LIST := $(shell go list ./... | grep -v /vendor/)
GIT_TAG=$(shell git describe --tags --abbrev=0)
GIT_COMMIT=$(shell git rev-parse --short HEAD)
SBOM_OUTPUT_DIR ?= sbom
SBOM_OUTPUT_PREFIX ?= nauthilus
SBOM_DOCKER_IMAGE ?= ghcr.io/croessner/nauthilus:latest
SBOM_DOCKER_PULL ?= true
SBOM_SYFT_VERSION ?= v1.16.0

export GOEXPERIMENT := greenteagc

.PHONY: all test race msan build build-client build-oidctestclient build-saml2testclient clean install uninstall sbom validate-templates install-hooks

all: build build-client build-oidctestclient build-saml2testclient

$(OUTPUT) $(CLIENT_OUTPUT) $(OIDCTESTCLIENT_OUTPUT) $(SAML2TESTCLIENT_OUTPUT):
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

build-oidctestclient: $(OIDCTESTCLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(OIDCTESTCLIENT_OUTPUT) ./contrib/oidctestclient

build-saml2testclient: $(SAML2TESTCLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(SAML2TESTCLIENT_OUTPUT) ./contrib/saml2testclient

sbom: ## Generate SBOMs (source and Docker image)
	./scripts/sbom.sh \
		--output-dir $(SBOM_OUTPUT_DIR) \
		--output-prefix $(SBOM_OUTPUT_PREFIX) \
		--source-dir . \
		--docker-image $(SBOM_DOCKER_IMAGE) \
		--docker-pull $(SBOM_DOCKER_PULL) \
		--syft-version $(SBOM_SYFT_VERSION)

clean: ## Remove previous build
	[ -x $(OUTPUT) ] && rm -f $(OUTPUT) || true
	[ -x $(CLIENT_OUTPUT) ] && rm -f $(CLIENT_OUTPUT) || true
	[ -x $(OIDCTESTCLIENT_OUTPUT) ] && rm -f $(OIDCTESTCLIENT_OUTPUT) || true
	[ -x $(SAML2TESTCLIENT_OUTPUT) ] && rm -f $(SAML2TESTCLIENT_OUTPUT) || true

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

validate-templates: ## Validate Go HTML templates for syntax errors
	go run scripts/validate-templates.go

install-hooks: ## Install Git hooks for development
	./scripts/install-hooks.sh

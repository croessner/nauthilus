OUTPUT := nauthilus/bin/nauthilus
CLIENT_OUTPUT := nauthilus/bin/nauthilus-client
OIDCTESTCLIENT_OUTPUT := nauthilus/bin/oidctestclient
SAML2TESTCLIENT_OUTPUT := nauthilus/bin/saml2testclient
HEALTHCHECK_OUTPUT := nauthilus/bin/nauthilus-healthcheck
GIT_TAG=$(shell git describe --tags --abbrev=0)
GIT_COMMIT=$(shell git rev-parse --short HEAD)
SBOM_OUTPUT_DIR ?= sbom
SBOM_OUTPUT_PREFIX ?= nauthilus
SBOM_DOCKER_IMAGE ?= ghcr.io/croessner/nauthilus:latest
SBOM_DOCKER_PULL ?= true
SBOM_SYFT_VERSION ?= v1.16.0

export GOEXPERIMENT := runtimesecret

.PHONY: all fix vet test race msan build build-client build-oidctestclient build-saml2testclient build-healthcheck clean install uninstall sbom validate-templates install-hooks

all: build build-client build-oidctestclient build-saml2testclient build-healthcheck

fix: ## Run go fix to apply automated code migrations
	go fix ./...

vet: ## Run go vet for static analysis
	go vet ./...

$(OUTPUT) $(CLIENT_OUTPUT) $(OIDCTESTCLIENT_OUTPUT) $(SAML2TESTCLIENT_OUTPUT) $(HEALTHCHECK_OUTPUT):
	mkdir -p $(dir $@)

test:
	go test -short $$(go list ./... | grep -v /vendor/)

race:
	go test -race -short $$(go list ./... | grep -v /vendor/)

msan:
	go test -msan -short $$(go list ./... | grep -v /vendor/)

build: fix vet $(OUTPUT)
	go build -mod=vendor -trimpath -v -ldflags "-X main.buildTime=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') -X main.version=$(GIT_TAG)-$(GIT_COMMIT)" -o $(OUTPUT) ./server

build-client: $(CLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(CLIENT_OUTPUT) ./client

build-oidctestclient: $(OIDCTESTCLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(OIDCTESTCLIENT_OUTPUT) ./contrib/oidctestclient

build-saml2testclient: $(SAML2TESTCLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(SAML2TESTCLIENT_OUTPUT) ./contrib/saml2testclient

build-healthcheck: $(HEALTHCHECK_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(HEALTHCHECK_OUTPUT) ./docker-healthcheck

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
	[ -x $(HEALTHCHECK_OUTPUT) ] && rm -f $(HEALTHCHECK_OUTPUT) || true

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

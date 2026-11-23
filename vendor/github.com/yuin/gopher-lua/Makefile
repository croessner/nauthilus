.PHONY: build generate glua test test-race test-short vet bench bench-upstream bench-external \
	fuzz FORCE

# vm.go and state.go are generated from _vm.go and _state.go by the
# function inliner. Edit the underscore files and run "make generate".
generate:
	./_tools/go-inline *.go
	gofmt -w vm.go state.go

build: generate
	go build ./...

glua: generate
	go build -o glua ./cmd/glua

vet:
	go vet ./...

test:
	go test -count=1 ./...

test-short:
	go test -count=1 -short ./...

test-race:
	go test -count=1 -race -short ./...

fuzz:
	go test -run xxx -fuzz FuzzJIT -fuzztime 60s .

# Benchmarks: this runtime, upstream GopherLua, stand-alone interpreters.
bench:
	cd benchmarks && go test -run xxx -bench . -benchmem .

bench-upstream:
	cd benchmarks && GOFLAGS=-mod=mod go test -modfile=go.upstream.mod -tags upstream -run xxx -bench . -benchmem .

bench-external:
	cd benchmarks && for lua in lua5.5 luajit; do \
		if command -v $$lua >/dev/null; then echo "== $$lua"; $$lua harness.lua; fi; done

# Run the test suite on Linux through Docker (arm64 is emulated on x86
# hosts and vice versa).
# (Phony targets are not matched by pattern rules, hence FORCE.)
test-linux-%: FORCE
	mkdir -p .cross
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go test -c -o .cross/lua.linux-$*.test .
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go test -c -o .cross/jit.linux-$*.test ./internal/jit
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go test -c -o .cross/codecache.linux-$*.test ./internal/jit/codecache
	docker run --rm --platform linux/$* -v $(CURDIR):/src -w /src alpine:3 sh -c \
		'/src/.cross/codecache.linux-$*.test -test.count=1 -test.short && /src/.cross/jit.linux-$*.test -test.count=1 && /src/.cross/lua.linux-$*.test -test.count=1 -test.short'

FORCE:

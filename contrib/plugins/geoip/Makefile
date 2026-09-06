GO ?= go
PLUGIN_OUT ?= build/geoip.so

.PHONY: build test clean

build:
	mkdir -p $(dir $(PLUGIN_OUT))
	NATIVE_ARTIFACT_LDFLAGS="$$(cd ../../.. && GOEXPERIMENT=runtimesecret $(GO) run -mod=vendor ./scripts/native_artifact_fingerprint)" && \
	GOEXPERIMENT=runtimesecret $(GO) build -mod=vendor -trimpath -ldflags "$$NATIVE_ARTIFACT_LDFLAGS" -buildmode=plugin -o $(PLUGIN_OUT) .

test:
	GOEXPERIMENT=runtimesecret $(GO) test .

clean:
	rm -rf build

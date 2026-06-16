GO ?= go
PLUGIN_OUT ?= build/geoip.so

.PHONY: build test clean

build:
	mkdir -p $(dir $(PLUGIN_OUT))
	GOEXPERIMENT=runtimesecret $(GO) build -buildmode=plugin -o $(PLUGIN_OUT) .

test:
	GOEXPERIMENT=runtimesecret $(GO) test .

clean:
	rm -rf build

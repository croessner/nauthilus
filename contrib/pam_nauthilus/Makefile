GO ?= go
LIBDIR ?= /lib/security
TARGET ?= pam_nauthilus.so

.PHONY: build install clean test

build:
	CGO_ENABLED=1 $(GO) build -buildmode=c-shared -o $(TARGET)

install: build
	install -m 0644 $(TARGET) $(LIBDIR)/$(TARGET)

clean:
	rm -f $(TARGET) pam_nauthilus.h

test:
	$(GO) test ./...

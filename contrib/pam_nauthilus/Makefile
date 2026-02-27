CC      ?= gcc
LIBDIR  ?= /lib/security
TARGET  ?= pam_nauthilus.so

CFLAGS  ?= -Wall -Wextra -Werror -fPIC -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
CFLAGS  += $(shell pkg-config --cflags libcurl openssl libcjson 2>/dev/null)
LDFLAGS += -shared $(shell pkg-config --libs libcurl openssl libcjson 2>/dev/null) -lpam

SRCS    = pam_nauthilus.c config.c http_client.c flow.c jwks.c
OBJS    = $(SRCS:.c=.o)

.PHONY: build install clean test

build: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: build
	install -m 0644 $(TARGET) $(LIBDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)

test:
	@echo "No unit tests yet for the C implementation."

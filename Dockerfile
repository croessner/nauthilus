FROM golang:1.22-alpine3.19 AS builder

WORKDIR /build

COPY . ./

# Set necessarry environment vairables and compile the app
ENV CGO_ENABLED=1 GOOS=linux GOARCH=amd64
RUN apk add --no-cache build-base
RUN cd server && go build -mod=vendor -tags="sonic avx" -ldflags="-s" -o nauthilus .
RUN cd docker-healthcheck && go build -mod=vendor -ldflags="-s" -o healthcheck .
RUN cd contrib/smtp-server && go build -mod=vendor -ldflags="-s" -o fakesmtp .
RUN cd contrib/imap-server && go build -mod=vendor -ldflags="-s" -o fakeimap .

FROM alpine:3.19
#FROM golang:1.22-alpine3.19

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"
LABEL description="Multi purpose authentication server"

WORKDIR /usr/app

RUN addgroup -S nauthilus; \
    adduser -S nauthilus -G nauthilus -D -H -s /bin/nologin

RUN apk --no-cache --upgrade add ca-certificates

# Debugging with pprof
#COPY --from=builder ["/build", "/build"]

# Copy binary to destination image
COPY --from=builder ["/build/server/nauthilus", "./"]
COPY --from=builder ["/build/server/resources", "./resources/"]
COPY --from=builder ["/build/server/lua-plugins.d", "./lua-plugins.d/"]
COPY --from=builder ["/build/docker-healthcheck/healthcheck", "./"]
COPY --from=builder ["/build/contrib/smtp-server/fakesmtp", "./"]
COPY --from=builder ["/build/contrib/imap-server/fakeimap", "./"]
COPY --from=builder ["/build/static/", "./static/"]
COPY --from=builder ["/usr/local/go/lib/time/zoneinfo.zip", "/"]

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
RUN echo 'hosts: files dns' > /etc/nsswitch.conf

ENV ZONEINFO=/zoneinfo.zip

EXPOSE 8180

USER nauthilus

CMD ["/usr/app/nauthilus"]

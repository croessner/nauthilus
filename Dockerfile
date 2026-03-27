FROM --platform=$BUILDPLATFORM golang:1.26-alpine3.22 AS builder

ARG BUILD_TAGS=""
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

COPY . ./

# Set necessarry environment vairables and compile the app
ENV CGO_ENABLED=0
ENV GOEXPERIMENT=runtimesecret
RUN apk add --no-cache build-base git upx

RUN GIT_TAG=$(git describe --tags --abbrev=0) && echo "tag="${GIT_TAG}"" && \
    GIT_COMMIT=$(git rev-parse --short HEAD) && echo "commit="${GIT_COMMIT}"" && \
    cd server && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -tags="netgo ${BUILD_TAGS}" \
    -trimpath \
    -ldflags="-s -w -X main.buildTime=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -X main.version=${GIT_TAG}-${GIT_COMMIT}" \
    -o nauthilus . && \
    upx --best --lzma nauthilus

RUN cd client && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o nauthilus-client . && upx --best --lzma nauthilus-client
RUN cd contrib/oidctestclient && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o oidctestclient . && upx --best --lzma oidctestclient
RUN cd contrib/saml2testclient && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o saml2testclient . && upx --best --lzma saml2testclient

RUN cd docker-healthcheck && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o healthcheck . && upx --best --lzma healthcheck
RUN cd contrib/smtp-server && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o fakesmtp . && upx --best --lzma fakesmtp
RUN cd contrib/imap-server && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o fakeimap . && upx --best --lzma fakeimap

FROM alpine:3

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL org.opencontainers.image.source="https://github.com/croessner/nauthilus"
LABEL org.opencontainers.image.description="Authentication and identity platform with OIDC, SAML, MFA, LDAP, Lua, and mail integrations"
LABEL org.opencontainers.image.licenses=GPL3
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"

WORKDIR /usr/app

RUN addgroup -S nauthilus; \
    adduser -S nauthilus -G nauthilus -D -H -s /bin/nologin

RUN apk --no-cache --upgrade add ca-certificates bash curl

# Copy binary to destination image
COPY --from=builder ["/build/server/nauthilus", "/build/client/nauthilus-client", "/build/contrib/oidctestclient/oidctestclient", "/build/contrib/saml2testclient/saml2testclient", "./"]
COPY --from=builder ["/build/server/resources", "./server/resources/"]
COPY --from=builder ["/build/server/lua-plugins.d", "./server/lua-plugins.d/"]
COPY --from=builder ["/build/docker-healthcheck/healthcheck", "./"]
COPY --from=builder ["/build/contrib/smtp-server/fakesmtp", "./"]
COPY --from=builder ["/build/contrib/imap-server/fakeimap", "./"]
COPY --from=builder ["/build/static/", "./static/"]

RUN ln -s ./server/lua-plugins.d ./lua-plugins.d

COPY --from=builder ["/usr/local/go/lib/time/zoneinfo.zip", "/"]

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
RUN echo 'hosts: files dns' > /etc/nsswitch.conf

ENV ZONEINFO=/zoneinfo.zip
ENV TERM=xterm-256color

EXPOSE 8080

USER nauthilus

CMD ["/usr/app/nauthilus", "-config", "/etc/nauthilus/nauthilus.yml", "-config-format", "yaml"]

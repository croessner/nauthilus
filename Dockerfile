# syntax=docker/dockerfile:1.7

FROM --platform=$TARGETPLATFORM golang:1.26-alpine3.24 AS builder

ARG BUILD_TAGS=""
ARG REQUIRE_PLUGIN_SIGNATURE=false
ARG TARGETOS
ARG TARGETARCH
ARG NAUTHILUS_CONF_DIR=/etc/nauthilus
ARG NAUTHILUS_PLUGINS_DIR=/usr/app/lua-plugins.d

WORKDIR /build

COPY . ./

# Set necessary environment variables and compile the app.
ENV CGO_ENABLED=1
ENV GOEXPERIMENT=runtimesecret
RUN apk add --no-cache build-base git upx

RUN GIT_TAG=$(git describe --tags --abbrev=0) && echo "tag="${GIT_TAG}"" && \
    GIT_COMMIT=$(git rev-parse --short HEAD) && echo "commit="${GIT_COMMIT}"" && \
    cd server && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -tags="netgo ${BUILD_TAGS}" \
    -trimpath \
    -ldflags="-s -w -X main.buildTime=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -X main.version=${GIT_TAG}-${GIT_COMMIT} -X github.com/croessner/nauthilus/server/config.nauthilusConfDir=${NAUTHILUS_CONF_DIR} -X github.com/croessner/nauthilus/server/config.nauthilusPluginsDir=${NAUTHILUS_PLUGINS_DIR}" \
    -o nauthilus . && \
    upx --best --lzma nauthilus

RUN mkdir -p /usr/local/lib/nauthilus/plugins && \
    cd contrib/plugins/geoip && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -tags="netgo ${BUILD_TAGS}" -buildmode=plugin -trimpath -o /usr/local/lib/nauthilus/plugins/geoip.so .

RUN --mount=type=secret,id=plugin_signing_private_key \
    if [ "${REQUIRE_PLUGIN_SIGNATURE}" = "true" ]; then \
      test -s /run/secrets/plugin_signing_private_key && \
      go run -mod=vendor ./server/pluginloader/cmd/nauthilus-plugin-sign sign \
        --artifact /usr/local/lib/nauthilus/plugins/geoip.so \
        --signature /usr/local/lib/nauthilus/plugins/geoip.so.minisig \
        --private-key-file /run/secrets/plugin_signing_private_key; \
    fi

RUN cd client && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o nauthilus-client . && upx --best --lzma nauthilus-client
RUN cd contrib/oidctestclient && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o oidctestclient . && upx --best --lzma oidctestclient
RUN cd contrib/saml2testclient && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o saml2testclient . && upx --best --lzma saml2testclient

RUN cd docker-healthcheck && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o healthcheck . && upx --best --lzma healthcheck
RUN cd contrib/smtp-server && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o fakesmtp . && upx --best --lzma fakesmtp
RUN cd contrib/imap-server && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=vendor -trimpath -ldflags="-s -w" -o fakeimap . && upx --best --lzma fakeimap

FROM alpine:3.24

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL org.opencontainers.image.source="https://github.com/croessner/nauthilus"
LABEL org.opencontainers.image.description="Authentication and identity platform with OIDC, SAML, MFA, LDAP, Lua, and mail integrations"
LABEL org.opencontainers.image.licenses=GPL3
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"

WORKDIR /usr/app

RUN addgroup -S -g 65532 nauthilus && \
    adduser -S -D -H -h /nonexistent -s /sbin/nologin -G nauthilus -u 65532 nauthilus && \
    apk --no-cache --upgrade add ca-certificates && \
    printf 'hosts: files dns\n' > /etc/nsswitch.conf

# Copy binary to destination image
COPY --from=builder ["/build/server/nauthilus", "/build/client/nauthilus-client", "/build/contrib/oidctestclient/oidctestclient", "/build/contrib/saml2testclient/saml2testclient", "./"]
COPY --from=builder ["/build/server/resources", "./server/resources/"]
COPY --from=builder ["/build/server/resources/security-policy.md", "./server/resources/security-policy.md"]
COPY --from=builder ["/build/server/lua-plugins.d", "./server/lua-plugins.d/"]
COPY --from=builder ["/build/docker-healthcheck/healthcheck", "./"]
COPY --from=builder ["/build/contrib/smtp-server/fakesmtp", "./"]
COPY --from=builder ["/build/contrib/imap-server/fakeimap", "./"]
COPY --from=builder ["/build/static/", "./static/"]
COPY --from=builder ["/usr/local/lib/nauthilus/plugins/", "/usr/local/lib/nauthilus/plugins/"]

COPY --from=builder ["/usr/local/go/lib/time/zoneinfo.zip", "/"]

RUN ln -s ./server/lua-plugins.d ./lua-plugins.d && \
    ln -s ./server/resources ./resources

ENV ZONEINFO=/zoneinfo.zip
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV TZ=UTC
ENV TERM=xterm-256color

EXPOSE 8080

USER 65532:65532

CMD ["/usr/app/nauthilus", "-config", "/etc/nauthilus/nauthilus.yml", "-config-format", "yaml"]

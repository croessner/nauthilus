FROM --platform=$BUILDPLATFORM golang:1.23-alpine3.20 AS builder

WORKDIR /build

COPY . ./

# Set necessarry environment vairables and compile the app
ENV CGO_ENABLED=0
RUN apk add --no-cache build-base git

RUN GIT_TAG=$(git describe --tags --abbrev=0) && echo "tag="${GIT_TAG}"" && \
    GIT_COMMIT=$(git rev-parse --short HEAD) && echo "commit="${GIT_COMMIT}"" && \
    cd server && go build -mod=vendor -tags="register2fa" -ldflags="-s -X main.version=${GIT_TAG}-${GIT_COMMIT}" -o nauthilus .

RUN cd docker-healthcheck && go build -mod=vendor -ldflags="-s" -o healthcheck .
RUN cd contrib/smtp-server && go build -mod=vendor -ldflags="-s" -o fakesmtp .
RUN cd contrib/imap-server && go build -mod=vendor -ldflags="-s" -o fakeimap .

FROM --platform=$BUILDPLATFORM alpine:3

LABEL org.opencontainers.image.authors="christian@roessner.email"
LABEL org.opencontainers.image.source="https://github.com/croessner/nauthilus"
LABEL org.opencontainers.image.description="Multi purpose authentication server"
LABEL org.opencontainers.image.licenses=GPL3
LABEL com.roessner-network-solutions.vendor="Rößner-Network-Solutions"

WORKDIR /usr/app

RUN addgroup -S nauthilus; \
    adduser -S nauthilus -G nauthilus -D -H -s /bin/nologin

RUN apk --no-cache --upgrade add ca-certificates bash curl

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
ENV TERM=xterm-256color

EXPOSE 8180

USER nauthilus

CMD ["/usr/app/nauthilus"]

# syntax=docker/dockerfile:1.7
# Build the Vue application and controller into one management image. Node is
# a build dependency only; the Go process serves the compiled static assets.
FROM node:22-alpine AS web

WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY apps/web ./
RUN npm run build

FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false -ldflags='-s -w' \
    -o /out/homelab-proxy-controller ./cmd/controller

FROM alpine:3.20

RUN addgroup -S -g 10001 controller \
    && adduser -S -D -H -u 10001 -G controller controller \
    && mkdir -p /var/lib/homelab-proxy-controller \
    && chown controller:controller /var/lib/homelab-proxy-controller \
    && apk add --no-cache ca-certificates

COPY --from=build /out/homelab-proxy-controller /usr/local/bin/homelab-proxy-controller
COPY --from=web /src/apps/web/dist /usr/share/egressdeck/web

USER 10001:10001
WORKDIR /var/lib/homelab-proxy-controller
ENV LISTEN_ADDR=:8080 \
    AUTH_MODE=session \
    COOKIE_SECURE=true \
    STATIC_DIR=/usr/share/egressdeck/web
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/homelab-proxy-controller"]

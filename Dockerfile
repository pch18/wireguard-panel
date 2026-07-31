FROM node:22-alpine AS web-builder
WORKDIR /build/web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM golang:1.23-alpine AS server-builder
WORKDIR /build
COPY srv/go.mod srv/go.sum ./srv/
RUN cd srv && go mod download
COPY srv/ ./srv/
COPY --from=web-builder /build/srv/web ./srv/web
RUN cd srv && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app .

FROM alpine:3.22
RUN apk add --no-cache wireguard-tools \
    && install -d -m 0700 /etc/wireguard
WORKDIR /app
COPY --from=server-builder /app /usr/local/bin/app
ENV APP_PORT=8080 \
    APP_USERNAME=admin \
    APP_PASSWORD=admin \
    APP_COOKIE_SECURE=false \
    WG_CONFIG_DIR=/etc/wireguard \
    GIN_MODE=release
VOLUME ["/etc/wireguard"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/app"]

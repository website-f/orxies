# Multi-stage build with two final targets:
#   runtime → lean control plane + edge (`orxies serve`), unprivileged
#   agent   → adds the docker CLI + nixpacks for `orxies agent`
#
# ---- builder ----
# Go 1.25 required by modernc.org/sqlite (the pure-Go SQLite driver that
# keeps the binary CGO-free / statically linked).
FROM golang:1.25-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY . .
ARG VERSION=dev
# go.mod + go.sum are committed, so this is deterministic + cache-friendly.
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/orxies ./cmd/orxies

# ---- runtime (serve): lean, non-root ----
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S orxies && adduser -S -G orxies -u 1001 orxies
COPY --from=builder /out/orxies /usr/local/bin/orxies
RUN mkdir -p /etc/orxies/sites /etc/orxies/certs /etc/orxies/www /etc/orxies/data && \
    chown -R orxies:orxies /etc/orxies
USER orxies
EXPOSE 80 443 8090
ENTRYPOINT ["/usr/local/bin/orxies"]
CMD ["serve", "--data", "/etc/orxies"]

# ---- agent: privileged; talks to Docker + builds images ----
# Runs as root because it needs the mounted /var/run/docker.sock. Keep it
# internal (no published ports); it only serves a unix socket the control
# plane dials. This is the single component that holds Docker access.
FROM runtime AS agent
USER root
# docker CLI + buildx drive builds (Nixpacks emits BuildKit Dockerfiles);
# git covers providers that shell to it.
RUN apk add --no-cache docker-cli docker-cli-buildx git ca-certificates
# Nixpacks gives zero-config builds for Node/Next/Python/Go/PHP/etc. We
# install a PINNED, statically-linked musl binary (Alpine-compatible) for
# the target arch and verify it at build time — deterministic, no flaky
# install script. Bump NIXPACKS_VERSION to upgrade.
ARG NIXPACKS_VERSION=1.41.0
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) narch=x86_64 ;; \
      arm64) narch=aarch64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/railwayapp/nixpacks/releases/download/v${NIXPACKS_VERSION}/nixpacks-v${NIXPACKS_VERSION}-${narch}-unknown-linux-musl.tar.gz"; \
    wget -qO /tmp/nixpacks.tgz "$url"; \
    tar -xzf /tmp/nixpacks.tgz -C /usr/local/bin nixpacks; \
    rm /tmp/nixpacks.tgz; \
    chmod +x /usr/local/bin/nixpacks; \
    nixpacks --version
ENTRYPOINT ["/usr/local/bin/orxies"]
CMD ["agent", "--socket", "/run/orxies/agent.sock", "--data", "/etc/orxies"]

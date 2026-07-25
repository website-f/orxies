# Multi-stage build: tiny final image, no Go toolchain at runtime.
# ---- builder ----
FROM golang:1.22-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY . .
ARG VERSION=dev
# The repo ships go.mod + go.sum, so `go mod download` is deterministic
# and hits the layer cache. `go mod tidy` stays as a belt-and-suspenders
# reconcile in case go.mod drifts; it's idempotent when the sum is present.
RUN go mod download && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/jobcloud ./cmd/jobcloud

# ---- runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S jobcloud && adduser -S -G jobcloud -u 1001 jobcloud
COPY --from=builder /out/jobcloud /usr/local/bin/jobcloud
# Default data dir; mount your real one over this in docker-compose.
RUN mkdir -p /etc/jobcloud /etc/jobcloud/sites /etc/jobcloud/certs /etc/jobcloud/www && \
    chown -R jobcloud:jobcloud /etc/jobcloud
USER jobcloud
EXPOSE 80 443 8090
ENTRYPOINT ["/usr/local/bin/jobcloud"]
CMD ["serve", "--data", "/etc/jobcloud"]

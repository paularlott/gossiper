# syntax=docker/dockerfile:1
ARG DOCKER_HUB

# The API description and reference (web/dist), embedded in the binary; the same on every platform.
FROM --platform=${BUILDPLATFORM} ${DOCKER_HUB}library/node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY web/ ./
RUN npm run build

# Built on the build machine's platform and cross-compiled for the target, so a multi-platform build needs no emulation.
FROM --platform=${BUILDPLATFORM} ${DOCKER_HUB}library/golang:1.27.3-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG BUILT_AT
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X github.com/paularlott/gossiper/build.Date=${BUILT_AT}" -o /gossiper ./cmd/gossiper
RUN mkdir -p /data

# Distroless: the static binary, CA certificates, time zones and a nonroot user; no shell, no package manager.
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /gossiper /gossiper
# Writable state: --history-db and --database (tenants), e.g. /data/history.db and /data/tenants.db, and the
# self-signed certificate (HTTPS by default; GOSSIPER_HTTP_ONLY=true behind a proxy that terminates TLS).
COPY --from=build --chown=nonroot:nonroot /data /data
VOLUME ["/data"]
ENV GOSSIPER_TLS_DIR=/data/tls
EXPOSE 8080 7946/tcp 7946/udp
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s CMD ["/gossiper", "healthcheck"]
ENTRYPOINT ["/gossiper"]
CMD ["serve"]

# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/relayd ./cmd/relayd \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/relayd /usr/local/bin/relayd
# Pre-create the data directory owned by the distroless nonroot user (65532)
# so the volume is writable without running as root.
COPY --from=build --chown=65532:65532 /out/data /var/lib/webhook-relay
# The write-ahead log lives here; mount a persistent volume in production.
VOLUME ["/var/lib/webhook-relay"]
ENV RELAY_ADDR=:8080 \
    RELAY_DATA_DIR=/var/lib/webhook-relay \
    RELAY_FSYNC=always
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/relayd"]

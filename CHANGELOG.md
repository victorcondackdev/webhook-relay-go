# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-21

### Added

- `signature`: Standard Webhooks compatible signing and verification
  (`webhook-id`, `webhook-timestamp`, `webhook-signature`), HMAC-SHA256 `v1`
  with `whsec_` secrets and ed25519 `v1a` with `whsk_`/`whpk_` keys, multiple
  active keys for rotation, timestamp tolerance, constant-time comparison and
  an HTTP middleware for receivers.
- `wal`: segmented append-only log with CRC32-C framing, torn-write recovery,
  corruption detection in older segments, `always`/`interval`/`never` fsync
  policies and group commit.
- `relay`: delivery engine with durable `Store` interface, file-backed store
  on the WAL (replay on start, crash-safe compaction with retention) and an
  in-memory store; at-least-once delivery, retry schedule with jitter,
  `Retry-After`, `410 Gone` handling, dead-letter queue with manual retry and
  replay, per-endpoint circuit breaker, concurrency limit, token-bucket rate
  limit and optional FIFO ordering; SSRF guard checking resolved and
  connected addresses; Prometheus metrics, slog logging and `traceparent`
  propagation.
- `api` and `cmd/relayd`: HTTP API for endpoints, messages (idempotent by
  key), attempts, replay and the DLQ, with problem+json errors, bearer token
  authentication and graceful shutdown that drains in-flight deliveries.
- `examples/receiver`: merchant-side consumer that verifies signatures and
  deduplicates on `webhook-id`.
- CI (Go 1.22 and stable, gofmt, vet, race tests with a coverage gate, fuzz
  smoke, Docker build), distroless non-root Docker image, Dependabot.

[0.1.0]: https://github.com/victorcondackdev/webhook-relay-go/releases/tag/v0.1.0

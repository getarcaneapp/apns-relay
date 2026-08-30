# Arcane APNs Relay

A small Go service that delivers Arcane's mobile push notifications to iOS devices without ever
learning where a user's Arcane server lives or who they are.

- A **manager** (an Arcane backend) registers a public key and gets an opaque `channelId`.
- A **device** enrolls its APNs token and gets an opaque `installationId` + secret.
- The device **pairs** the two with a short-lived token signed by the manager, receiving a `recipientId`.
- The manager sends **signed envelopes** naming recipient ids; the relay verifies, dedupes, queues and
  pushes them over a persistent HTTP/2 connection to APNs.

What the relay stores: channel public keys, encrypted device tokens, recipient bindings, and a
short-lived delivery queue (payloads are deleted once sent). What it never sees: server URLs,
user identities, credentials, or the contents of your Docker environment beyond the notification text.

The full request/response contract is documented separately (see `../apns-relay-docs/PROTOCOL.md` in the workspace).

## Running

```sh
just gen-key                     # -> RELAY_ENCRYPTION_KEY
cp relay.example.yaml relay.yaml # fill in apns.* and encryption_key
just run                         # go run ./cmd -config relay.yaml
```

Or purely from the environment:

```sh
RELAY_ENCRYPTION_KEY=<hex> APNS_KEY_ID=... APNS_TEAM_ID=... APNS_KEY_FILE=AuthKey.p8 ./apns-relay
```

`just dev` starts the relay in `APNS_MODE=log`, which accepts everything and logs deliveries
instead of contacting Apple — enough to exercise the API locally.

### Configuration

Configuration is a YAML file (`-config path` or `RELAY_CONFIG`) with environment variable
overrides. Precedence: defaults < file < env. See [`relay.example.yaml`](relay.example.yaml) for
every key; the env names are the YAML keys upper-cased with a `RELAY_` prefix (`APNS_` for the
`apns` block), e.g. `rate_limits.channel_per_minute` → `RELAY_RATE_LIMIT_CHANNEL_PER_MINUTE`.

| Key | Env | Default | Notes |
|---|---|---|---|
| `listen` | `RELAY_LISTEN_ADDR` | `:3554` | |
| `database_path` | `RELAY_DATABASE_PATH` | `./data/relay.db` | SQLite (WAL); pure Go, no CGO |
| `encryption_key` / `encryption_key_file` | `RELAY_ENCRYPTION_KEY` / `_FILE` | — | 32 bytes hex/base64; AES-256-GCM for device tokens |
| `max_envelope_age` | `RELAY_MAX_ENVELOPE_AGE` | `5m` | reject stale envelopes |
| `max_body_bytes` | `RELAY_MAX_BODY_BYTES` | `65536` | |
| `workers` | `RELAY_WORKERS` | `8` | concurrent APNs sends |
| `max_attempts` | `RELAY_MAX_ATTEMPTS` | `8` | retries for 5xx/429 |
| `retention` | `RELAY_RETENTION` | `24h` | finished deliveries & event-id dedupe window |
| `trust_proxy_headers` | `RELAY_TRUST_PROXY_HEADERS` | `false` | use `X-Forwarded-For` for IP limits |
| `log.level` / `log.format` | `RELAY_LOG_LEVEL` / `RELAY_LOG_FORMAT` | `info` / `json` | |
| `rate_limits.*` | `RELAY_RATE_LIMIT_*_PER_MINUTE` | 60 / 600 / 60 | per IP / channel / installation |
| `apns.mode` | `APNS_MODE` | `live` | `log` disables sending |
| `apns.key_id`, `apns.team_id` | `APNS_KEY_ID`, `APNS_TEAM_ID` | — | from the Apple developer portal |
| `apns.topic` | `APNS_TOPIC` | `com.getarcaneapp.ios.mobile` | bundle id |
| `apns.key` / `apns.key_file` | `APNS_KEY_P8` / `APNS_KEY_FILE` | — | the `.p8` auth key (ES256 / P-256) |
| `apns.sandbox_url`, `apns.production_url` | `APNS_SANDBOX_URL`, `APNS_PRODUCTION_URL` | Apple hosts | override for testing |

### Docker

```sh
docker run -p 3554:3554 -v relay-data:/app/data -v ./relay.yaml:/app/config/relay.yaml:ro \
  -v ./AuthKey.p8:/run/secrets/AuthKey.p8:ro ghcr.io/getarcaneapp/apns-relay:latest
```

The image is built by goreleaser (`.goreleaser.yaml`, `docker/Dockerfile-static`) the same way
Arcane's images are, on top of `gcr.io/distroless/static-debian13:nonroot` (the relay is a static
binary, so it does not need Arcane's larger base image). `Dockerfile` at the root is a plain local build.
Note the image runs as `nonroot`, so the `/app/data` volume must be writable by uid 65532.

## Observability

- `GET /healthz` — database ping + pending queue depth.
- `GET /metrics` — Prometheus text: accepted/duplicate/rejected events, queued/sent/retried/failed/dropped
  deliveries, APNs responses by status+reason, invalid-token removals, rate-limit hits, queue latency.
- Logs never contain device tokens, payload bodies, or request bodies.

## Cryptography notes

- **Manager ↔ relay** signatures are Ed25519 by default; **ML-DSA-87** (FIPS 204, via Go's
  `crypto/mldsa`) is accepted as an alternative channel algorithm — the CNSA 2.0-approved parameter set.
- **Relay ↔ Apple** provider tokens are ES256 (ECDSA P-256). This is the only algorithm APNs
  accepts, so it cannot be swapped for ML-DSA.
- Device tokens are encrypted at rest with AES-256-GCM, bound to their installation id.
- Installation secrets are stored as SHA-256 hashes (they are 256-bit random values).

## Development

```sh
just test      # go test -race ./...
just lint      # go vet + golangci-lint
just snapshot  # goreleaser snapshot build
```

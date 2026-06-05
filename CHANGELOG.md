# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-06-05

Docs/metadata release — the published library and CLI (`dist/`) are unchanged
from 0.1.0.

### Added

- A **browser playground** — paste a JWT to decode, audit and verify it fully
  client-side (signatures via the Web Crypto API, nothing uploaded). Live at
  <https://didrod205.github.io/jwtlens/>. README now links it.
- Internal: the playground source (`web/`, built to `docs/` for GitHub Pages) and
  a Web Crypto verification test. These are not part of the npm package.

## [0.1.0] - 2026-06-05

Initial public release.

### Added

- **Offline decode** of JWS compact tokens (header / payload / signature), with
  clear errors for malformed input and JWE detection.
- **Security lint**: `alg: none`, signed-header-with-no-signature, unknown alg,
  symmetric-alg (HS↔RS alg-confusion) awareness, missing/over-long `exp`, future
  `iat`, missing `aud`/`iss`/`sub`/`jti`, and expired / not-yet-valid status — each
  with a fix and human-readable timing ("expired 3h ago", "in 15m").
- **Offline signature verification** via `node:crypto` for HS256/384/512, RS*,
  PS*, ES256/384/512 (raw IEEE-P1363 signatures) and EdDSA, using a shared secret,
  a PEM public key, or a JWK/JWKS (selected by `kid`).
- Token extraction from a bare token, an `Authorization: Bearer` header, or a log
  line. Dependency-free, browser-safe base64url + decode + lint core.
- `scan` / `verify` / `report` / `init` CLI with JSON/Markdown export, a CI score
  gate, a `--now` flag for deterministic timing, and config files. Full library API.

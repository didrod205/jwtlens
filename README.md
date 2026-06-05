<div align="center">

# 🔍 jwtlens

### Decode, audit & verify JWTs — entirely offline. Stop pasting live tokens into jwt.io.

[![npm version](https://img.shields.io/npm/v/jwtlens.svg?color=success)](https://www.npmjs.com/package/jwtlens)
[![CI](https://github.com/didrod205/jwtlens/actions/workflows/ci.yml/badge.svg)](https://github.com/didrod205/jwtlens/actions/workflows/ci.yml)
[![types](https://img.shields.io/npm/types/jwtlens.svg)](https://www.npmjs.com/package/jwtlens)
[![license](https://img.shields.io/npm/l/jwtlens.svg)](./LICENSE)

</div>

An API rejects your request, so you grab the JWT from a log line and — to read its
claims — paste it into **jwt.io**. That token is a **production credential**, and
you just sent it to a third-party website. Then you eyeball `exp`/`aud`/`alg` by
hand, and to actually check the signature you'd need the key loaded *somewhere*.

**jwtlens decodes, security-audits, and *verifies* a JWT entirely on your
machine.** No website, no API key, no network. Decode + lint are pure; signature
verification runs locally via `node:crypto` with **your own secret, PEM, or JWK**.

```bash
echo "$TOKEN" | npx jwtlens scan --key public.pem
```

```
Header
  alg      "RS256"     typ "JWT"     kid "k1"
Payload
  iss      "https://auth.example.com"
  sub      "user-4012"
  exp      1893456900  (in 15m)
  iat      1893456000  (in 0s)

Status     active
Signature  ✓ verified (RS256) — signature matches the supplied key
Score  100/100 (A)
```

---

## Why jwtlens?

- 🔒 **Offline by design.** Your token (and your signing key) never leave the
  machine — the whole reason not to use jwt.io for a live credential.
- ✅ **It verifies, not just decodes.** Real `node:crypto` signature checks for
  **HS256/384/512, RS*, PS*, ES256/384/512 and EdDSA** — including the ECDSA raw
  (P1363) signature format that trips up naive verifiers.
- 🛡️ **It audits the security posture.** `alg: none`, a signed header with no
  signature, no/over-long `exp`, future-dated `iat`, missing `aud`/`iss`/`sub`/
  `jti`, and the HS↔RS **alg-confusion** trap — each with the fix.
- 🤖 **Deterministic & CI-ready.** Same token → same result. Gate your issuer in
  CI: fail the build if it ever emits `alg: none` or a forever-token.

Why not ask an LLM? base64url, claim timing, and **signature math** are exact — a
chatbot can't (and shouldn't) hold your secret to verify a signature, and you need
this on every token, in CI, not once.

## Install

```bash
# run it now
echo "$TOKEN" | npx jwtlens scan

# or add it
npm install -g jwtlens      # global CLI
npm install -D jwtlens      # CI / library
```

Node ≥ 18. Decode + lint are dependency-free and browser-safe; verification uses
`node:crypto`.

## Quick start

```bash
jwtlens scan "$TOKEN"                          # decode + security lint
echo "$TOKEN" | jwtlens scan                   # from stdin (Bearer prefix ok)
jwtlens scan token.txt --key public.pem        # + verify RS/ES/EdDSA
jwtlens scan "$TOKEN" --secret "$HS_SECRET"    # + verify HS*
jwtlens verify token.txt --jwk jwks.json       # just verify (exit 0/1)
jwtlens scan "$TOKEN" --now 2030-01-01         # evaluate timing at a fixed date
jwtlens scan "$TOKEN" --min-score 80 --md report.md   # CI gate + report
```

See [`examples/sample-report.md`](./examples/sample-report.md) and the bundled
`examples/*.jwt.txt` (a strong RS256 token, a weak HS256 one, and an `alg: none`).

## What it checks

| Group | Examples |
| ----- | -------- |
| **Signature & algorithm** | `alg: none` (error), signed header with empty signature, unknown alg, symmetric-alg (alg-confusion) warning |
| **Expiry & timing** | missing `exp` (never expires), over-long lifetime, `iat` in the future |
| **Claims** | missing `aud` / `iss` / `sub` / `jti` |
| **Token status** | expired, not-yet-valid (`nbf`), with human-readable "3h ago" / "in 15m" |
| **Verification** | local signature check with `--secret` / `--key` (PEM) / `--jwk` (JWK or JWKS, by `kid`) |

Findings roll up to a 0–100 score and an A–F grade you can gate in CI.

## Real scenarios

**1. Inspect a prod token safely.** Pull it from a log, pipe it in, read the
claims and timing — without handing the credential to a website.

```bash
kubectl logs api | grep -o 'eyJ[^ ]*' | head -1 | jwtlens scan
```

**2. Verify a token's signature locally.** Confirm a token really came from your
issuer using the public JWKS, offline:

```bash
jwtlens verify "$TOKEN" --jwk jwks.json && echo "authentic"
```

**3. Gate your issuer in CI.** Assert the tokens your auth service mints are
well-formed (signed, short-lived, scoped):

```bash
your-cli mint-test-token | npx jwtlens scan --min-score 85
```

## Configuration

`jwtlens init` writes `jwtlens.config.json`:

```jsonc
{
  "ignore": [],                 // rule ids to skip, e.g. ["no-jti"]
  "maxLifetimeSeconds": 86400,  // warn above this token lifetime
  "clockSkewSeconds": 60,       // tolerance for iat/nbf "in the future"
  "minScore": 0                 // CI gate threshold
}
```

## Library API

```ts
import { analyzeToken, verifyJwt, decodeJwt, DEFAULT_CONFIG } from "jwtlens";

const now = Math.floor(Date.now() / 1000);
const { decoded, findings } = analyzeToken(token, DEFAULT_CONFIG, now);
const result = verifyJwt(decoded, { secret: process.env.HS_SECRET });
console.log(result.valid, findings.map((f) => f.rule));
```

`decodeJwt` and `lintJwt` are pure (browser-safe); `verifyJwt` uses `node:crypto`.

## Roadmap

- 🤖 **Optional `--ai` layer (bring-your-own key)** to explain a token's claims in
  context. The core stays 100% offline and deterministic.
- Fetch a JWKS from an `iss`/`.well-known` URL (explicit opt-in; off by default).
- `x5c`/`x5t` certificate-chain awareness and key-type/alg mismatch checks.
- Encrypted JWE structure inspection (header only).
- A web playground that runs `decode` + `lint` fully client-side (nothing uploaded).

## 💖 Sponsor

jwtlens is free and MIT-licensed, built and maintained in spare time. If it kept a
live token off a third-party website, please consider supporting it:

- ⭐ **Star this repo** — the simplest free way to help others find it.
- 🍋 **[Sponsor via Lemon Squeezy](https://elab-studio.lemonsqueezy.com/checkout/buy/5d059b89-51d0-456b-b33a-ed56994f7010)** — one-time or recurring.

## License

[MIT](./LICENSE) © jwtlens contributors

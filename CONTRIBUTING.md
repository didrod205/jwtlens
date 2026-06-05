# Contributing to jwtlens

Thanks for your interest! Most contributions are a new lint rule or a new
signature algorithm — both small and isolated.

## Getting started

```bash
git clone https://github.com/didrod205/jwtlens.git
cd jwtlens
npm install
npm test            # vitest (generates real HS/RS/ES tokens to verify)
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/
echo "$TOKEN" | node dist/cli.js scan
```

## Project layout

```
src/
  base64url.ts   # dependency-free, universal base64url codec
  decode.ts      # JWS compact → header / payload / signature
  claims.ts      # registered-claim helpers + duration/relative-time formatting
  lint.ts        # the security rule set (alg/exp/claims), deterministic via `now`
  verify.ts      # offline signature verification (node:crypto): HS/RS/PS/ES/EdDSA
  extract.ts     # find a token in a Bearer header / log line
  analyze.ts     # orchestrator + report builder (pure)
  score.ts       # weighted score + grade
  config.ts      # pure defaults/merge      load-config.ts # fs loading
  loader.ts      # read token + key material (Node)
  report/        # console (inspector view) / json / markdown
  cli.ts         # cac CLI (scan / verify / report / init)
tests/           # vitest specs (incl. real crypto round-trips)
examples/        # strong (RS256) / weak (HS256) / none tokens + public.pem
```

## Adding a lint rule

Add it to `src/lint.ts` returning a `Finding` (stable `rule`, severity, a `fix`).
Timing rules take the injected `now` — never call `Date.now()` in the analysis, so
tests stay deterministic. Add a test in `tests/lint.test.ts`.

## Adding an algorithm

Extend `verifyJwt` in `src/verify.ts` and `KNOWN_ALGS` in `src/lint.ts`. Add a test
in `tests/verify.test.ts` that signs a token with `node:crypto` and verifies it.

## Quality bar

- [ ] Crypto changes have a real sign→verify round-trip test (and a wrong-key one).
- [ ] The analysis is deterministic (timing via `now`, no `Date.now()` in `src/lint`).
- [ ] `npm run typecheck && npm test && npm run build` all pass.
- [ ] Never log or transmit a token or key. Offline is the whole point.

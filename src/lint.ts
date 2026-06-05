/**
 * The security rule set. Given a decoded JWT, flag the things that make a token
 * forgeable, dangerous, or sloppily scoped: `alg: none`, a signed alg with no
 * signature, no/over-long expiry, future-dated issuance, and missing audience/
 * issuer/subject/replay claims. Timing is evaluated against an injected `now`
 * so the analysis is deterministic and testable.
 */

import { hasClaim, numClaim, relativeTime } from "./claims.js";
import type { Config, DecodedJwt, Finding } from "./types.js";

const KNOWN_ALGS = new Set([
  "HS256", "HS384", "HS512",
  "RS256", "RS384", "RS512",
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
  "EdDSA",
]);

export function lintJwt(decoded: DecodedJwt, config: Config, now: number): Finding[] {
  const out: Finding[] = [];
  const { header, payload } = decoded;
  const alg = typeof header.alg === "string" ? header.alg : "";

  // --- signature & algorithm ---
  if (!alg) {
    out.push({
      rule: "alg-missing",
      category: "signature",
      severity: "error",
      title: "No `alg` in the header",
      message: "Without an algorithm, the token can't be verified meaningfully.",
      fix: "Issue tokens with an explicit asymmetric alg (e.g. RS256/ES256).",
    });
  } else if (alg.toLowerCase() === "none") {
    out.push({
      rule: "alg-none",
      category: "signature",
      severity: "error",
      title: "`alg: none` — the token is unsigned",
      message: "An unsecured JWT has no signature; anyone can forge it. Servers must reject `none`.",
      fix: "Sign tokens with RS256/ES256 and reject any token whose alg is `none`.",
    });
  } else if (!KNOWN_ALGS.has(alg)) {
    out.push({
      rule: "alg-unknown",
      category: "signature",
      severity: "warning",
      title: `Unrecognized algorithm \`${alg}\``,
      message: "This isn't a standard JWA algorithm — verify your issuer and library support it.",
    });
  } else if (decoded.signatureBytes === 0) {
    out.push({
      rule: "no-signature",
      category: "signature",
      severity: "error",
      title: `\`${alg}\` header but no signature`,
      message: "The token claims to be signed but the signature segment is empty — it can't be trusted.",
    });
  }

  if (alg.startsWith("HS")) {
    out.push({
      rule: "symmetric-alg",
      category: "signature",
      severity: "info",
      title: `Symmetric algorithm (${alg})`,
      message: "HMAC uses a shared secret. Keep it private, and never let the verifier accept other algs — an RS↔HS alg-confusion attack can forge tokens with your public key.",
      fix: "Prefer asymmetric (RS256/ES256), and pin the expected alg on the verifier.",
    });
  }

  // --- expiry & timing ---
  const exp = numClaim(payload, "exp");
  const iat = numClaim(payload, "iat");
  const nbf = numClaim(payload, "nbf");

  if (exp === undefined) {
    out.push({
      rule: "no-exp",
      category: "expiry",
      severity: "warning",
      title: "No `exp` — the token never expires",
      message: "A stolen token without an expiry is valid forever.",
      fix: "Set a short `exp` (minutes for access tokens).",
    });
  } else if (iat !== undefined && exp - iat > config.maxLifetimeSeconds) {
    const hours = Math.round((exp - iat) / 3600);
    out.push({
      rule: "long-lifetime",
      category: "expiry",
      severity: "warning",
      title: `Long-lived token (~${hours}h)`,
      message: "Long lifetimes widen the blast radius if the token leaks.",
      fix: "Issue short-lived access tokens and use refresh tokens for longevity.",
    });
  }

  if (iat !== undefined && iat > now + config.clockSkewSeconds) {
    out.push({
      rule: "iat-future",
      category: "expiry",
      severity: "warning",
      title: "`iat` is in the future",
      message: `Issued-at is ${relativeTime(iat, now)} — clock skew, or a forged/replayed token.`,
    });
  }

  // --- claims ---
  for (const [claim, label] of [
    ["aud", "audience"],
    ["iss", "issuer"],
    ["sub", "subject"],
  ] as const) {
    if (!hasClaim(payload, claim)) {
      out.push({
        rule: `no-${claim}`,
        category: "claims",
        severity: "info",
        title: `No \`${claim}\` (${label})`,
        message: `Without \`${claim}\`, the token isn't scoped to a ${label}.`,
        fix: `Include \`${claim}\` and validate it on the server.`,
      });
    }
  }
  if (!hasClaim(payload, "jti")) {
    out.push({
      rule: "no-jti",
      category: "claims",
      severity: "info",
      title: "No `jti` (token id)",
      message: "Without a unique id, you can't revoke or replay-protect individual tokens.",
    });
  }

  // --- status (informational state, lightly weighted) ---
  if (exp !== undefined && exp <= now) {
    out.push({
      rule: "expired",
      category: "status",
      severity: "info",
      title: `Expired (${relativeTime(exp, now)})`,
      message: "This token is past its `exp` and should be rejected by any compliant server.",
    });
  }
  if (nbf !== undefined && nbf > now + config.clockSkewSeconds) {
    out.push({
      rule: "not-yet-valid",
      category: "status",
      severity: "info",
      title: `Not valid yet (${relativeTime(nbf, now)})`,
      message: "The `nbf` (not-before) is in the future, so the token isn't active yet.",
    });
  }

  return out;
}

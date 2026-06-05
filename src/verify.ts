/**
 * Offline JWS signature verification. Given a decoded token and a key (a shared
 * secret for HMAC algorithms, or a public key — PEM or JWK/JWKS — for RSA, RSA-PSS,
 * ECDSA and EdDSA), verify the signature locally with `node:crypto`. Nothing leaves
 * the machine, and you never have to paste the token into a website to know if it's
 * authentic.
 */

import {
  constants,
  createHmac,
  createPublicKey,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { base64UrlToBytes, bytesToBase64Url } from "./base64url.js";
import type { DecodedJwt, VerifyResult } from "./types.js";

export interface KeyInput {
  /** Shared secret for HMAC (HS*) algorithms. */
  secret?: string;
  /** A PEM-encoded public (or private) key for RSA/RSA-PSS/ECDSA/EdDSA. */
  pem?: string;
  /** A JWK or JWKS object. */
  jwk?: unknown;
}

function hashFor(alg: string): string {
  const bits = alg.slice(-3);
  if (bits === "256") return "sha256";
  if (bits === "384") return "sha384";
  if (bits === "512") return "sha512";
  throw new Error(`unsupported algorithm "${alg}"`);
}

type Candidate =
  | { kind: "hmac"; secret: Uint8Array | string }
  | { kind: "key"; key: KeyObject };

function jwkCandidates(jwk: unknown, kid?: string): Candidate[] {
  const keys = Array.isArray((jwk as { keys?: unknown[] })?.keys)
    ? ((jwk as { keys: unknown[] }).keys)
    : [jwk];
  let chosen = keys as Record<string, unknown>[];
  if (kid) {
    const byKid = chosen.filter((k) => k.kid === kid);
    if (byKid.length) chosen = byKid;
  }
  const out: Candidate[] = [];
  for (const k of chosen) {
    if (k.kty === "oct" && typeof k.k === "string") {
      out.push({ kind: "hmac", secret: base64UrlToBytes(k.k) });
    } else {
      try {
        const jwkInput = { key: k, format: "jwk" } as unknown as Parameters<typeof createPublicKey>[0];
        out.push({ kind: "key", key: createPublicKey(jwkInput) });
      } catch {
        /* skip unusable jwk */
      }
    }
  }
  return out;
}

function candidatesFor(input: KeyInput, header: Record<string, unknown>): Candidate[] {
  if (input.secret !== undefined) return [{ kind: "hmac", secret: input.secret }];
  if (input.pem) return [{ kind: "key", key: createPublicKey(input.pem) }];
  if (input.jwk !== undefined) {
    return jwkCandidates(input.jwk, typeof header.kid === "string" ? header.kid : undefined);
  }
  return [];
}

function verifyOne(alg: string, signingInput: string, sig: Uint8Array, cand: Candidate): boolean {
  const data = Buffer.from(signingInput, "ascii");
  const sigBuf = Buffer.from(sig);
  const fam = alg.slice(0, 2);

  if (fam === "HS") {
    if (cand.kind !== "hmac") return false;
    const expected = createHmac(hashFor(alg), cand.secret).update(data).digest();
    return expected.length === sigBuf.length && timingSafeEqual(expected, sigBuf);
  }
  if (cand.kind !== "key") return false;

  try {
    if (fam === "RS") {
      return cryptoVerify(hashFor(alg), data, cand.key, sigBuf);
    }
    if (fam === "PS") {
      return cryptoVerify(
        hashFor(alg),
        data,
        { key: cand.key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
        sigBuf,
      );
    }
    if (fam === "ES") {
      // JWS ECDSA signatures are raw r||s (IEEE P1363), not DER.
      return cryptoVerify(hashFor(alg), data, { key: cand.key, dsaEncoding: "ieee-p1363" }, sigBuf);
    }
    if (alg === "EdDSA") {
      return cryptoVerify(null, data, cand.key, sigBuf);
    }
  } catch {
    return false;
  }
  return false;
}

export function verifyJwt(decoded: DecodedJwt, input: KeyInput): VerifyResult {
  const alg = typeof decoded.header.alg === "string" ? decoded.header.alg : "";
  if (!alg) return { valid: false, alg: "", reason: "no `alg` in the header" };
  if (alg.toLowerCase() === "none") {
    return { valid: false, alg, reason: "`alg: none` is unsigned — there is nothing to verify (reject it)" };
  }

  let candidates: Candidate[];
  try {
    candidates = candidatesFor(input, decoded.header);
  } catch (e) {
    return { valid: false, alg, reason: `could not load key: ${(e as Error).message}` };
  }
  if (candidates.length === 0) {
    return { valid: false, alg, reason: "no key supplied (use --secret, --key or --jwk)" };
  }

  const sig = base64UrlToBytes(decoded.parts.signature);
  if (sig.length === 0) return { valid: false, alg, reason: "the token has no signature" };

  const wantsSecret = alg.startsWith("HS");
  for (const cand of candidates) {
    if (wantsSecret && cand.kind !== "hmac") {
      return { valid: false, alg, reason: `${alg} needs a shared secret (--secret), not a public key` };
    }
    if (!wantsSecret && cand.kind !== "key") {
      return { valid: false, alg, reason: `${alg} needs a public key (--key/--jwk), not a secret` };
    }
    try {
      if (verifyOne(alg, decoded.signingInput, sig, cand)) {
        return { valid: true, alg, reason: "signature matches the supplied key" };
      }
    } catch (e) {
      return { valid: false, alg, reason: (e as Error).message };
    }
  }
  return { valid: false, alg, reason: "signature does not match the supplied key" };
}

/** Re-export for callers that want to recompute an HMAC signature. */
export { bytesToBase64Url };

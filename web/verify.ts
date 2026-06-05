/**
 * In-browser JWS signature verification via the Web Crypto API (SubtleCrypto).
 * The whole point of the playground: verify a token's signature **client-side**,
 * so neither the token nor your key is ever uploaded. Supports HS/RS/PS/ES with
 * a shared secret, a PEM public key, or a JWK.
 */

import { base64UrlToBytes } from "../src/base64url.js";

export type KeyMaterial =
  | { kind: "secret"; secret: string }
  | { kind: "pem"; pem: string }
  | { kind: "jwk"; jwk: unknown };

export interface BrowserVerifyResult {
  valid: boolean;
  reason: string;
}

const HASH: Record<string, string> = { "256": "SHA-256", "384": "SHA-384", "512": "SHA-512" };
const CURVE: Record<string, string> = { ES256: "P-256", ES384: "P-384", ES512: "P-521" };
const SALT: Record<string, number> = { "256": 32, "384": 48, "512": 64 };

function pemToDer(pem: string): BufferSource {
  const body = pem.replace(/-----(BEGIN|END)[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(body);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out as BufferSource;
}

function bytes(s: string): BufferSource {
  return new TextEncoder().encode(s) as BufferSource;
}

async function importKey(alg: string, key: KeyMaterial): Promise<CryptoKey> {
  const fam = alg.slice(0, 2);
  const hash = HASH[alg.slice(-3)] ?? "SHA-256";

  if (fam === "HS") {
    if (key.kind === "secret") {
      return crypto.subtle.importKey("raw", bytes(key.secret), { name: "HMAC", hash }, false, ["verify"]);
    }
    if (key.kind === "jwk") {
      return crypto.subtle.importKey("jwk", key.jwk as JsonWebKey, { name: "HMAC", hash }, false, ["verify"]);
    }
    throw new Error("HS* needs a shared secret");
  }

  const algParams: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams =
    fam === "RS"
      ? { name: "RSASSA-PKCS1-v1_5", hash }
      : fam === "PS"
        ? { name: "RSA-PSS", hash }
        : fam === "ES"
          ? { name: "ECDSA", namedCurve: CURVE[alg] ?? "P-256" }
          : (() => { throw new Error(`unsupported algorithm ${alg} (verify EdDSA in the CLI)`); })();

  if (key.kind === "jwk") {
    return crypto.subtle.importKey("jwk", key.jwk as JsonWebKey, algParams, false, ["verify"]);
  }
  if (key.kind === "pem") {
    return crypto.subtle.importKey("spki", pemToDer(key.pem), algParams, false, ["verify"]);
  }
  throw new Error(`${alg} needs a public key (PEM or JWK), not a secret`);
}

export async function verifyInBrowser(
  signingInput: string,
  signatureB64u: string,
  alg: string,
  key: KeyMaterial,
): Promise<BrowserVerifyResult> {
  if (!alg) return { valid: false, reason: "no alg in header" };
  if (alg.toLowerCase() === "none") return { valid: false, reason: "alg:none is unsigned — reject it" };

  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await importKey(alg, key);
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }

  const fam = alg.slice(0, 2);
  const hash = HASH[alg.slice(-3)] ?? "SHA-256";
  const verifyParams: AlgorithmIdentifier | RsaPssParams | EcdsaParams =
    fam === "HS"
      ? { name: "HMAC" }
      : fam === "RS"
        ? { name: "RSASSA-PKCS1-v1_5" }
        : fam === "PS"
          ? { name: "RSA-PSS", saltLength: SALT[alg.slice(-3)] ?? 32 }
          : { name: "ECDSA", hash };

  try {
    const sig = base64UrlToBytes(signatureB64u) as BufferSource;
    const ok = await crypto.subtle.verify(verifyParams, cryptoKey, sig, bytes(signingInput));
    return { valid: ok, reason: ok ? "signature matches the supplied key" : "signature does not match the supplied key" };
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
}

/**
 * Parse a JWT (JWS compact serialization) into its decoded header, payload and
 * signature — without verifying anything. Returns an `error` for malformed
 * input (wrong segment count, non-JSON header/payload, or a JWE).
 */

import { base64UrlToBytes, base64UrlToString } from "./base64url.js";
import type { DecodedJwt } from "./types.js";

function parseJson(part: string, label: string): Record<string, unknown> {
  const text = base64UrlToString(part);
  const value = JSON.parse(text) as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

export function decodeJwt(token: string): DecodedJwt {
  const raw = token.trim();
  const parts = raw.split(".");

  const empty: DecodedJwt = {
    parts: { header: parts[0] ?? "", payload: parts[1] ?? "", signature: parts[2] ?? "" },
    header: {},
    payload: {},
    signingInput: `${parts[0] ?? ""}.${parts[1] ?? ""}`,
    signatureBytes: 0,
  };

  if (parts.length === 5) {
    return { ...empty, error: "This is a JWE (5 segments, encrypted) — jwtlens reads signed JWTs (JWS)." };
  }
  if (parts.length !== 3) {
    return { ...empty, error: `Expected 3 dot-separated segments, found ${parts.length}.` };
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = parseJson(parts[0]!, "header");
  } catch (e) {
    return { ...empty, error: `Invalid header: ${(e as Error).message}` };
  }
  try {
    payload = parseJson(parts[1]!, "payload");
  } catch (e) {
    return { ...empty, header, error: `Invalid payload: ${(e as Error).message}` };
  }

  let signatureBytes = 0;
  try {
    signatureBytes = parts[2] ? base64UrlToBytes(parts[2]).length : 0;
  } catch {
    signatureBytes = 0;
  }

  return {
    parts: { header: parts[0]!, payload: parts[1]!, signature: parts[2]! },
    header,
    payload,
    signingInput: `${parts[0]}.${parts[1]}`,
    signatureBytes,
  };
}

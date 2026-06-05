/**
 * Verifies the playground's in-browser Web Crypto path. Node 20+ exposes the
 * same `globalThis.crypto.subtle`, so we can exercise web/verify.ts here.
 */
import { describe, expect, it } from "vitest";
import { createHmac, createSign, generateKeyPairSync } from "node:crypto";
import { decodeJwt } from "../src/decode.js";
import { verifyInBrowser } from "../web/verify.js";

const b64u = (b: Buffer) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const enc = (o: unknown) => b64u(Buffer.from(JSON.stringify(o)));

function hsToken(secret: string): string {
  const si = `${enc({ alg: "HS256", typ: "JWT" })}.${enc({ sub: "x" })}`;
  return `${si}.${b64u(createHmac("sha256", secret).update(si).digest())}`;
}

async function verify(token: string, alg: string, key: Parameters<typeof verifyInBrowser>[3]) {
  const d = decodeJwt(token);
  return verifyInBrowser(d.signingInput, d.parts.signature, alg, key);
}

describe("verifyInBrowser (Web Crypto)", () => {
  it("verifies and rejects HS256 secrets", async () => {
    expect((await verify(hsToken("s3cret"), "HS256", { kind: "secret", secret: "s3cret" })).valid).toBe(true);
    expect((await verify(hsToken("s3cret"), "HS256", { kind: "secret", secret: "wrong" })).valid).toBe(false);
  });

  it("verifies RS256 with a PEM public key", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const si = `${enc({ alg: "RS256", typ: "JWT" })}.${enc({ sub: "x" })}`;
    const token = `${si}.${b64u(createSign("RSA-SHA256").update(si).sign(privateKey))}`;
    const pem = publicKey.export({ type: "spki", format: "pem" }) as string;
    expect((await verify(token, "RS256", { kind: "pem", pem })).valid).toBe(true);
  });

  it("verifies ES256 (raw P1363) with a JWK", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const si = `${enc({ alg: "ES256", typ: "JWT" })}.${enc({ sub: "x" })}`;
    const sig = createSign("SHA256").update(si).sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
    const token = `${si}.${b64u(sig)}`;
    const jwk = publicKey.export({ format: "jwk" });
    expect((await verify(token, "ES256", { kind: "jwk", jwk })).valid).toBe(true);
  });

  it("never verifies alg:none", async () => {
    const token = `${enc({ alg: "none" })}.${enc({ sub: "x" })}.`;
    expect((await verify(token, "none", { kind: "secret", secret: "x" })).valid).toBe(false);
  });
});

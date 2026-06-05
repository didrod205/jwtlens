import { describe, expect, it } from "vitest";
import { createHmac, createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { decodeJwt } from "../src/decode.js";
import { verifyJwt } from "../src/verify.js";

const b64u = (b: Buffer) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const enc = (o: unknown) => b64u(Buffer.from(JSON.stringify(o)));

function hsToken(secret: string): string {
  const si = `${enc({ alg: "HS256", typ: "JWT" })}.${enc({ sub: "x" })}`;
  return `${si}.${b64u(createHmac("sha256", secret).update(si).digest())}`;
}

function signed(alg: string, signAlg: string, priv: KeyObject, opts: Record<string, unknown> = {}): string {
  const si = `${enc({ alg, typ: "JWT" })}.${enc({ sub: "x" })}`;
  const sig = createSign(signAlg).update(si).sign({ key: priv, ...opts });
  return `${si}.${b64u(sig)}`;
}

describe("verifyJwt — HMAC", () => {
  it("verifies a correct HS256 secret", () => {
    expect(verifyJwt(decodeJwt(hsToken("s3cret")), { secret: "s3cret" }).valid).toBe(true);
  });
  it("rejects a wrong secret", () => {
    expect(verifyJwt(decodeJwt(hsToken("s3cret")), { secret: "nope" }).valid).toBe(false);
  });
  it("refuses to verify HS256 with a public key", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const r = verifyJwt(decodeJwt(hsToken("s")), { pem: publicKey.export({ type: "spki", format: "pem" }) as string });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/shared secret/);
  });
});

describe("verifyJwt — RSA / ECDSA", () => {
  it("verifies RS256 with the matching public key", () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const token = signed("RS256", "RSA-SHA256", privateKey);
    expect(verifyJwt(decodeJwt(token), { pem: publicKey.export({ type: "spki", format: "pem" }) as string }).valid).toBe(true);
  });

  it("rejects RS256 against a different key", () => {
    const a = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const b = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const token = signed("RS256", "RSA-SHA256", a.privateKey);
    expect(verifyJwt(decodeJwt(token), { pem: b.publicKey.export({ type: "spki", format: "pem" }) as string }).valid).toBe(false);
  });

  it("verifies ES256 (raw P1363 signature)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const token = signed("ES256", "SHA256", privateKey, { dsaEncoding: "ieee-p1363" });
    expect(verifyJwt(decodeJwt(token), { pem: publicKey.export({ type: "spki", format: "pem" }) as string }).valid).toBe(true);
  });

  it("verifies via a JWK (public key as JWK)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const token = signed("ES256", "SHA256", privateKey, { dsaEncoding: "ieee-p1363" });
    const jwk = publicKey.export({ format: "jwk" });
    expect(verifyJwt(decodeJwt(token), { jwk }).valid).toBe(true);
  });
});

describe("verifyJwt — none", () => {
  it("never verifies alg:none", () => {
    const token = `${enc({ alg: "none" })}.${enc({ sub: "x" })}.`;
    const r = verifyJwt(decodeJwt(token), { secret: "anything" });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/none/);
  });
});

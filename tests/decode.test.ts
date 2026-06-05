import { describe, expect, it } from "vitest";
import { decodeJwt } from "../src/decode.js";

const b64u = (obj: unknown) =>
  Buffer.from(JSON.stringify(obj)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

describe("decodeJwt", () => {
  it("decodes a well-formed token", () => {
    const token = `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u({ sub: "x", exp: 123 })}.sig`;
    const d = decodeJwt(token);
    expect(d.error).toBeUndefined();
    expect(d.header.alg).toBe("HS256");
    expect(d.payload.sub).toBe("x");
    expect(d.signatureBytes).toBeGreaterThan(0);
    expect(d.signingInput).toBe(token.split(".").slice(0, 2).join("."));
  });

  it("handles an unsigned (alg:none) token with an empty signature", () => {
    const d = decodeJwt(`${b64u({ alg: "none" })}.${b64u({ sub: "x" })}.`);
    expect(d.error).toBeUndefined();
    expect(d.signatureBytes).toBe(0);
  });

  it("errors on the wrong number of segments", () => {
    expect(decodeJwt("a.b").error).toMatch(/3 dot-separated/);
  });

  it("identifies a JWE (5 segments)", () => {
    expect(decodeJwt("a.b.c.d.e").error).toMatch(/JWE/);
  });

  it("errors on a non-JSON header", () => {
    expect(decodeJwt(`bm90anNvbg.${b64u({ a: 1 })}.s`).error).toMatch(/header/i);
  });

  it("errors when the payload is a JSON array, not an object", () => {
    const token = `${b64u({ alg: "HS256" })}.${b64u([1, 2, 3])}.s`;
    expect(decodeJwt(token).error).toMatch(/payload/i);
  });
});

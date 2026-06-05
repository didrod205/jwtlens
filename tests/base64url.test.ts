import { describe, expect, it } from "vitest";
import { base64UrlToBytes, base64UrlToString, bytesToBase64Url } from "../src/base64url.js";

describe("base64url", () => {
  it("decodes a JWT header segment to JSON text", () => {
    // base64url of {"alg":"HS256","typ":"JWT"}
    expect(base64UrlToString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")).toBe(
      '{"alg":"HS256","typ":"JWT"}',
    );
  });

  it("round-trips bytes through encode/decode", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 62, 63]);
    expect([...base64UrlToBytes(bytesToBase64Url(bytes))]).toEqual([...bytes]);
  });

  it("produces url-safe output with no padding", () => {
    const out = bytesToBase64Url(new Uint8Array([255, 255, 255]));
    expect(out).not.toMatch(/[+/=]/);
  });

  it("handles unpadded input", () => {
    expect(base64UrlToString("YQ")).toBe("a"); // "YQ==" → "a"
  });
});

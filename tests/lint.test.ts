import { describe, expect, it } from "vitest";
import { lintJwt } from "../src/lint.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { DecodedJwt } from "../src/types.js";

const NOW = 1_000_000_000;

function decoded(header: Record<string, unknown>, payload: Record<string, unknown>, sigBytes = 32): DecodedJwt {
  return { parts: { header: "", payload: "", signature: "" }, header, payload, signingInput: "", signatureBytes: sigBytes };
}
const rules = (h: Record<string, unknown>, p: Record<string, unknown>, sig = 32) =>
  lintJwt(decoded(h, p, sig), DEFAULT_CONFIG, NOW).map((f) => f.rule);

describe("lintJwt — signature", () => {
  it("flags alg:none as an error", () => {
    const f = lintJwt(decoded({ alg: "none" }, { exp: NOW + 100 }, 0), DEFAULT_CONFIG, NOW).find((x) => x.rule === "alg-none");
    expect(f?.severity).toBe("error");
  });

  it("flags a signed alg with no signature bytes", () => {
    expect(rules({ alg: "RS256" }, { exp: NOW + 100 }, 0)).toContain("no-signature");
  });

  it("notes symmetric algorithms (alg-confusion awareness)", () => {
    expect(rules({ alg: "HS256" }, { exp: NOW + 100 })).toContain("symmetric-alg");
  });

  it("flags an unknown algorithm", () => {
    expect(rules({ alg: "XX999" }, { exp: NOW + 100 })).toContain("alg-unknown");
  });
});

describe("lintJwt — expiry & timing", () => {
  it("warns when exp is missing", () => {
    expect(rules({ alg: "RS256" }, { sub: "x" })).toContain("no-exp");
  });

  it("warns on a long-lived token", () => {
    expect(rules({ alg: "RS256" }, { iat: NOW, exp: NOW + 90 * 24 * 3600 })).toContain("long-lifetime");
  });

  it("flags an iat in the future", () => {
    expect(rules({ alg: "RS256" }, { iat: NOW + 5000, exp: NOW + 9000 })).toContain("iat-future");
  });

  it("reports an expired token as status", () => {
    expect(rules({ alg: "RS256" }, { exp: NOW - 100 })).toContain("expired");
  });

  it("reports a not-yet-valid token", () => {
    expect(rules({ alg: "RS256" }, { nbf: NOW + 5000, exp: NOW + 9000 })).toContain("not-yet-valid");
  });
});

describe("lintJwt — claims", () => {
  it("flags missing aud/iss/sub/jti", () => {
    const r = rules({ alg: "RS256" }, { exp: NOW + 100 });
    expect(r).toEqual(expect.arrayContaining(["no-aud", "no-iss", "no-sub", "no-jti"]));
  });

  it("a complete, current token has no claim findings", () => {
    const r = rules({ alg: "RS256" }, {
      iss: "i", sub: "s", aud: "a", jti: "j", iat: NOW, exp: NOW + 300,
    });
    expect(r).toHaveLength(0);
  });
});

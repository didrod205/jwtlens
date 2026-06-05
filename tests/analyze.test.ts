import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeToken, buildReport } from "../src/analyze.js";
import { extractToken } from "../src/extract.js";
import { DEFAULT_CONFIG, parseConfig, mergeConfig } from "../src/config.js";
import { loadConfig } from "../src/load-config.js";

const b64u = (o: unknown) =>
  Buffer.from(JSON.stringify(o)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const token = (h: unknown, p: unknown) => `${b64u(h)}.${b64u(p)}.sig`;
const NOW = 1_000_000_000;

describe("extractToken", () => {
  it("returns a bare token unchanged", () => {
    const t = token({ alg: "HS256" }, { sub: "x" });
    expect(extractToken(t)).toBe(t);
  });
  it("strips a Bearer prefix", () => {
    const t = token({ alg: "HS256" }, { sub: "x" });
    expect(extractToken(`Bearer ${t}`)).toBe(t);
  });
  it("finds a token embedded in a log line", () => {
    const t = token({ alg: "HS256" }, { sub: "x" });
    expect(extractToken(`2026-01-01 auth header=${t} status=401`)).toBe(t);
  });
  it("returns null when there is no token", () => {
    expect(extractToken("just some text")).toBeNull();
  });
});

describe("analyzeToken", () => {
  it("decodes and lints a token deterministically", () => {
    const { decoded, findings } = analyzeToken(token({ alg: "RS256" }, { exp: NOW + 300, iat: NOW, sub: "s", iss: "i", aud: "a", jti: "j" }), DEFAULT_CONFIG, NOW);
    expect(decoded.header.alg).toBe("RS256");
    expect(findings).toHaveLength(0);
  });

  it("surfaces a parse error as an error finding", () => {
    const { findings } = analyzeToken("not.a.jwt", DEFAULT_CONFIG, NOW);
    expect(findings[0]!.rule).toBe("parse-error");
  });

  it("respects the ignore list", () => {
    const { findings } = analyzeToken(token({ alg: "none" }, { sub: "x" }), { ...DEFAULT_CONFIG, ignore: ["alg-none"] }, NOW);
    expect(findings.some((f) => f.rule === "alg-none")).toBe(false);
  });

  it("buildReport computes score, grade and carries header/payload", () => {
    const analysis = analyzeToken(token({ alg: "none" }, { sub: "x" }), DEFAULT_CONFIG, NOW);
    const report = buildReport(analysis, { version: "t", generatedAt: "now" });
    expect(report.tool).toBe("jwtlens");
    expect(report.summary.errors).toBeGreaterThan(0);
    expect(report.payload.sub).toBe("x");
  });
});

describe("config", () => {
  it("parses and merges over defaults", () => {
    const cfg = parseConfig(JSON.stringify({ minScore: 80, maxLifetimeSeconds: 900 }));
    expect(cfg.minScore).toBe(80);
    expect(cfg.maxLifetimeSeconds).toBe(900);
    expect(cfg.clockSkewSeconds).toBe(DEFAULT_CONFIG.clockSkewSeconds);
  });

  it("throws on invalid JSON and ignores undefined overrides", () => {
    expect(() => parseConfig("{ bad")).toThrow(/invalid config/);
    expect(mergeConfig(DEFAULT_CONFIG, { minScore: undefined as unknown as number }).minScore).toBe(0);
  });

  it("loadConfig reads an explicit file", () => {
    const dir = mkdtempSync(join(tmpdir(), "jwtlens-"));
    const file = join(dir, "jwtlens.config.json");
    writeFileSync(file, JSON.stringify({ minScore: 70 }));
    expect(loadConfig(file).minScore).toBe(70);
    rmSync(dir, { recursive: true, force: true });
  });
});

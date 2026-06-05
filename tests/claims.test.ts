import { describe, expect, it } from "vitest";
import { formatDuration, relativeTime, numClaim, hasClaim } from "../src/claims.js";

describe("formatDuration", () => {
  it("formats seconds, minutes, hours and days", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(90)).toBe("1m 30s");
    expect(formatDuration(3600)).toBe("1h");
    expect(formatDuration(90000)).toBe("1d 1h");
  });
});

describe("relativeTime", () => {
  it("describes past and future relative to now", () => {
    expect(relativeTime(1000, 100)).toBe("in 15m");
    expect(relativeTime(100, 1000)).toBe("15m ago");
  });
});

describe("claim helpers", () => {
  it("reads numeric claims, ignoring non-numbers", () => {
    expect(numClaim({ exp: 123 }, "exp")).toBe(123);
    expect(numClaim({ exp: "123" }, "exp")).toBeUndefined();
  });
  it("detects present (non-empty) claims", () => {
    expect(hasClaim({ aud: "api" }, "aud")).toBe(true);
    expect(hasClaim({ aud: "" }, "aud")).toBe(false);
    expect(hasClaim({ aud: [] }, "aud")).toBe(false);
    expect(hasClaim({}, "aud")).toBe(false);
  });
});

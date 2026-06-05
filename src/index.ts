/**
 * jwtlens — decode, audit and verify JWTs entirely offline. Decode + security
 * lint are dependency-free and browser-safe; signature verification uses
 * `node:crypto` so it runs without a network round-trip — never paste a live
 * token into a website again.
 *
 * ```ts
 * import { analyzeToken, verifyJwt, decodeJwt, DEFAULT_CONFIG } from "jwtlens";
 * const { decoded, findings } = analyzeToken(token, DEFAULT_CONFIG, Math.floor(Date.now()/1000));
 * const result = verifyJwt(decoded, { secret: "my-hmac-secret" });
 * ```
 */

export { decodeJwt } from "./decode.js";
export { lintJwt } from "./lint.js";
export { analyzeToken, buildReport, type Analysis } from "./analyze.js";
export { verifyJwt, type KeyInput } from "./verify.js";
export { extractToken } from "./extract.js";
export { base64UrlToBytes, base64UrlToString, bytesToBase64Url } from "./base64url.js";
export { numClaim, hasClaim, formatDuration, relativeTime } from "./claims.js";
export { scoreFindings, gradeFor } from "./score.js";
export { DEFAULT_CONFIG, CONFIG_FILENAMES, parseConfig, mergeConfig } from "./config.js";
export {
  CATEGORIES,
  CATEGORY_LABELS,
  type Category,
  type Config,
  type DecodedJwt,
  type Finding,
  type Report,
  type Severity,
  type VerifyResult,
} from "./types.js";

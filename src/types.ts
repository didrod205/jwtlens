/** Core types for jwtlens. */

export type Severity = "error" | "warning" | "info" | "pass";

export type Category = "signature" | "expiry" | "claims" | "status";

export const CATEGORIES: Category[] = ["signature", "expiry", "claims", "status"];

export const CATEGORY_LABELS: Record<Category, string> = {
  signature: "Signature & algorithm",
  expiry: "Expiry & timing",
  claims: "Claims",
  status: "Token status",
};

export interface Finding {
  rule: string;
  category: Category;
  severity: Severity;
  title: string;
  message: string;
  fix?: string;
}

/** A decoded (not necessarily verified) JWT. */
export interface DecodedJwt {
  /** The three raw base64url parts (header, payload, signature). */
  parts: { header: string; payload: string; signature: string };
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** The signing input `header.payload` (what a signature covers). */
  signingInput: string;
  /** Decoded signature bytes length (0 for alg:none / unsecured). */
  signatureBytes: number;
  /** Parse error, if the token was malformed. */
  error?: string;
}

export interface VerifyResult {
  /** Whether the signature is valid for the supplied key. */
  valid: boolean;
  /** The algorithm used (from the header). */
  alg: string;
  /** Human explanation (why it failed, or which key matched). */
  reason: string;
}

export interface Report {
  tool: "jwtlens";
  version: string;
  generatedAt: string;
  /** The decoded header & payload (for the JSON report). */
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Verification result, when a key was supplied. */
  verification?: VerifyResult;
  summary: {
    score: number;
    grade: string;
    errors: number;
    warnings: number;
    infos: number;
  };
  findings: Finding[];
}

export interface Config {
  /** Rule ids to ignore. */
  ignore: string[];
  /** Warn when a token's lifetime (exp - iat) exceeds this many seconds. */
  maxLifetimeSeconds: number;
  /** Allowed clock skew (seconds) before iat/nbf are considered "in the future". */
  clockSkewSeconds: number;
  /** CI gate: minimum overall score. */
  minScore: number;
}

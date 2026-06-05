/** Orchestrator: decode + lint a token and assemble a report (pure). */

import { decodeJwt } from "./decode.js";
import { lintJwt } from "./lint.js";
import { gradeFor, scoreFindings } from "./score.js";
import type { Config, DecodedJwt, Finding, Report, VerifyResult } from "./types.js";

const SEVERITY_ORDER: Record<string, number> = { error: 0, warning: 1, info: 2, pass: 3 };

export interface Analysis {
  decoded: DecodedJwt;
  findings: Finding[];
}

/** Decode and security-lint a token string (pure; `now` in epoch seconds). */
export function analyzeToken(token: string, config: Config, now: number): Analysis {
  const decoded = decodeJwt(token);

  if (decoded.error) {
    return {
      decoded,
      findings: [
        {
          rule: "parse-error",
          category: "signature",
          severity: "error",
          title: "Could not parse the JWT",
          message: decoded.error,
        },
      ],
    };
  }

  const ignore = new Set(config.ignore);
  const findings = lintJwt(decoded, config, now)
    .filter((f) => !ignore.has(f.rule))
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  return { decoded, findings };
}

export function buildReport(
  analysis: Analysis,
  meta: { version: string; generatedAt: string },
  verification?: VerifyResult,
): Report {
  const { decoded, findings } = analysis;
  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of findings) {
    if (f.severity === "error") counts.error++;
    else if (f.severity === "warning") counts.warning++;
    else if (f.severity === "info") counts.info++;
  }
  const score = scoreFindings(findings);

  return {
    tool: "jwtlens",
    version: meta.version,
    generatedAt: meta.generatedAt,
    header: decoded.header,
    payload: decoded.payload,
    verification,
    summary: {
      score,
      grade: gradeFor(score),
      errors: counts.error,
      warnings: counts.warning,
      infos: counts.info,
    },
    findings,
  };
}

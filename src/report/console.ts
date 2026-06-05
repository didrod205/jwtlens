/** Colored console output for `scan` — an inspector view + the lint findings. */

import pc from "picocolors";
import { numClaim, relativeTime } from "../claims.js";
import type { Report, Severity } from "../types.js";

const MARK: Record<Severity, string> = { error: "✗", warning: "⚠", info: "ℹ", pass: "✓" };

function color(severity: Severity, text: string): string {
  if (severity === "error") return pc.red(text);
  if (severity === "warning") return pc.yellow(text);
  if (severity === "info") return pc.blue(text);
  return pc.green(text);
}

function gradeColor(grade: string): (s: string) => string {
  if (grade === "A" || grade === "B") return pc.green;
  if (grade === "C" || grade === "D") return pc.yellow;
  return pc.red;
}

const TIME_CLAIMS = new Set(["exp", "iat", "nbf"]);

function renderClaims(obj: Record<string, unknown>, now: number): void {
  for (const [k, v] of Object.entries(obj)) {
    let value = JSON.stringify(v);
    if (value && value.length > 80) value = value.slice(0, 77) + "…";
    let suffix = "";
    if (TIME_CLAIMS.has(k) && typeof v === "number") suffix = pc.dim(`  (${relativeTime(v, now)})`);
    console.log(`  ${pc.cyan(k.padEnd(8))} ${value}${suffix}`);
  }
}

export function printReport(report: Report, now: number, quiet = false): void {
  console.log(pc.bold("\nHeader"));
  renderClaims(report.header, now);
  console.log(pc.bold("\nPayload"));
  renderClaims(report.payload, now);

  // Status line.
  const exp = numClaim(report.payload, "exp");
  const nbf = numClaim(report.payload, "nbf");
  let status = pc.green("active");
  if (exp !== undefined && exp <= now) status = pc.red(`expired ${relativeTime(exp, now)}`);
  else if (nbf !== undefined && nbf > now) status = pc.yellow(`not valid yet (${relativeTime(nbf, now)})`);
  console.log(`\n${pc.bold("Status")}     ${status}`);

  if (report.verification) {
    const v = report.verification;
    const label = v.valid ? pc.green("✓ verified") : pc.red("✗ not verified");
    console.log(`${pc.bold("Signature")}  ${label} ${pc.dim(`(${v.alg}) — ${v.reason}`)}`);
  } else {
    console.log(`${pc.bold("Signature")}  ${pc.dim("— not checked (pass --secret/--key/--jwk to verify)")}`);
  }

  if (!quiet && report.findings.length > 0) {
    console.log(pc.bold("\nFindings"));
    for (const f of report.findings) {
      console.log(`  ${color(f.severity, MARK[f.severity])} ${f.title} ${pc.dim(f.rule)}`);
      if (f.fix) console.log(`      ${pc.dim("→ " + f.fix.split("\n")[0])}`);
    }
  }

  const s = report.summary;
  const g = gradeColor(s.grade);
  console.log(
    `\n${pc.bold("Score")}  ${g(`${s.score}/100 (${s.grade})`)} ` +
      pc.dim(`· ${s.errors} error(s), ${s.warnings} warning(s), ${s.infos} info(s)`),
  );
}

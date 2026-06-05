/**
 * jwtlens playground — decode, audit and verify a JWT entirely in the browser.
 * Reuses the library's *pure* decode + lint modules; verification runs through
 * the Web Crypto API. Nothing is ever sent anywhere.
 */

import { numClaim, relativeTime } from "../src/claims.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { decodeJwt } from "../src/decode.js";
import { extractToken } from "../src/extract.js";
import { lintJwt } from "../src/lint.js";
import { gradeFor, scoreFindings } from "../src/score.js";
import type { DecodedJwt, Finding } from "../src/types.js";
import { verifyInBrowser, type KeyMaterial } from "./verify.js";

const SAMPLE =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0." +
  "r94n7Fwi3uut2jsq6w5ta3C1gaJHTOxe1VOqGLJtjQI";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const TIME_CLAIMS = new Set(["exp", "iat", "nbf"]);

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Minimal JSON syntax highlighter for the header/payload panes. */
function highlightJson(value: unknown): string {
  const json = esc(JSON.stringify(value, null, 2));
  return json.replace(
    /("(\\.|[^"\\])*"(\s*:)?|\b(true|false|null)\b|-?\d+(\.\d+)?([eE][+-]?\d+)?)/g,
    (m) => {
      let cls = "tok-num";
      if (/^"/.test(m)) cls = /:$/.test(m) ? "tok-key" : "tok-str";
      else if (/true|false/.test(m)) cls = "tok-bool";
      else if (/null/.test(m)) cls = "tok-null";
      return `<span class="${cls}">${m}</span>`;
    },
  );
}

function renderClaims(payload: Record<string, unknown>, now: number): string {
  const rows = Object.entries(payload).map(([k, v]) => {
    let extra = "";
    if (TIME_CLAIMS.has(k) && typeof v === "number") {
      const d = new Date(v * 1000).toISOString().replace(".000Z", "Z");
      extra = `<span class="claim-meta">${esc(d)} · ${esc(relativeTime(v, now))}</span>`;
    }
    return `<div class="claim"><span class="claim-key">${esc(k)}</span><span class="claim-val">${esc(
      JSON.stringify(v),
    )}</span>${extra}</div>`;
  });
  return rows.join("") || `<div class="muted">(empty)</div>`;
}

const ICON: Record<string, string> = { error: "✗", warning: "⚠", info: "ℹ", pass: "✓" };

function renderFindings(findings: Finding[]): string {
  if (findings.length === 0) return `<div class="ok">✓ No issues — well-formed and well-scoped.</div>`;
  return findings
    .map(
      (f) => `<div class="finding sev-${f.severity}">
        <span class="finding-icon">${ICON[f.severity]}</span>
        <div><div class="finding-title">${esc(f.title)}</div>
        <div class="finding-msg">${esc(f.message)}</div>
        ${f.fix ? `<div class="finding-fix">→ ${esc(f.fix)}</div>` : ""}</div>
      </div>`,
    )
    .join("");
}

let current: DecodedJwt | null = null;

function render(): void {
  const raw = $<HTMLTextAreaElement>("token").value;
  const out = $("output");
  const err = $("error");
  if (!raw.trim()) {
    out.classList.add("hidden");
    err.classList.add("hidden");
    current = null;
    return;
  }

  const token = extractToken(raw) ?? raw.trim();
  const decoded = decodeJwt(token);
  current = decoded;

  if (decoded.error) {
    err.textContent = `⚠ ${decoded.error}`;
    err.classList.remove("hidden");
    out.classList.add("hidden");
    return;
  }
  err.classList.add("hidden");
  out.classList.remove("hidden");

  const now = Math.floor(Date.now() / 1000);
  $("header").innerHTML = highlightJson(decoded.header);
  $("payload").innerHTML = renderClaims(decoded.payload, now);

  // Status.
  const exp = numClaim(decoded.payload, "exp");
  const nbf = numClaim(decoded.payload, "nbf");
  const statusEl = $("status");
  if (exp !== undefined && exp <= now) {
    statusEl.className = "status bad";
    statusEl.textContent = `expired ${relativeTime(exp, now)}`;
  } else if (nbf !== undefined && nbf > now) {
    statusEl.className = "status warn";
    statusEl.textContent = `not valid yet (${relativeTime(nbf, now)})`;
  } else {
    statusEl.className = "status good";
    statusEl.textContent = "active";
  }

  const findings = lintJwt(decoded, DEFAULT_CONFIG, now);
  const score = scoreFindings(findings);
  const grade = gradeFor(score);
  const badge = $("score");
  badge.textContent = `${score}/100 (${grade})`;
  badge.className = `score-badge grade-${grade}`;
  $("findings").innerHTML = renderFindings(findings);

  resetVerify();
}

function resetVerify(): void {
  const r = $("verify-result");
  r.className = "verify-result hidden";
  r.textContent = "";
}

async function onVerify(): Promise<void> {
  const r = $("verify-result");
  if (!current || current.error) return;
  const alg = typeof current.header.alg === "string" ? current.header.alg : "";
  const keyText = $<HTMLTextAreaElement>("key").value.trim();
  const kind = ($<HTMLSelectElement>("keytype").value || "secret") as KeyMaterial["kind"];

  if (!keyText) {
    r.className = "verify-result warn";
    r.textContent = "Enter a secret, a PEM public key, or a JWK first.";
    return;
  }

  let key: KeyMaterial;
  try {
    if (kind === "secret") key = { kind: "secret", secret: keyText };
    else if (kind === "pem") key = { kind: "pem", pem: keyText };
    else key = { kind: "jwk", jwk: JSON.parse(keyText) };
  } catch {
    r.className = "verify-result bad";
    r.textContent = "✗ That JWK isn't valid JSON.";
    return;
  }

  r.className = "verify-result muted";
  r.textContent = "verifying…";
  const result = await verifyInBrowser(current.signingInput, current.parts.signature, alg, key);
  r.className = `verify-result ${result.valid ? "good" : "bad"}`;
  r.textContent = `${result.valid ? "✓ verified" : "✗ not verified"} (${alg}) — ${result.reason}`;
}

function init(): void {
  $<HTMLTextAreaElement>("token").addEventListener("input", render);
  $("verify-btn").addEventListener("click", () => void onVerify());
  $("sample").addEventListener("click", () => {
    $<HTMLTextAreaElement>("token").value = SAMPLE;
    $<HTMLTextAreaElement>("key").value = "a-string-secret-at-least-256-bits-long";
    $<HTMLSelectElement>("keytype").value = "secret";
    render();
  });
  $("clear").addEventListener("click", () => {
    $<HTMLTextAreaElement>("token").value = "";
    $<HTMLTextAreaElement>("key").value = "";
    render();
  });
}

init();

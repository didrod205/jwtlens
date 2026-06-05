#!/usr/bin/env node
/** jwtlens command-line interface. */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { cac } from "cac";
import pc from "picocolors";
import pkg from "../package.json";
import { analyzeToken, buildReport } from "./analyze.js";
import { DEFAULT_CONFIG } from "./config.js";
import { extractToken } from "./extract.js";
import { loadConfig } from "./load-config.js";
import { parseNow, readKeyInput, readTokenInput, type KeyOptions } from "./loader.js";
import { printReport } from "./report/console.js";
import { toJSON } from "./report/json.js";
import { toMarkdown } from "./report/markdown.js";
import { verifyJwt } from "./verify.js";
import type { Config, Report, VerifyResult } from "./types.js";

const cli = cac("jwtlens");

function fail(message: string): never {
  console.error(`${pc.red("jwtlens:")} ${message}`);
  process.exit(2);
}

interface CommonKeyOpts extends KeyOptions {
  now?: string;
}

function resolveToken(input: string | undefined): string {
  if (!input && process.stdin.isTTY) {
    fail("provide a token, a file, or pipe one via stdin (e.g. echo $TOKEN | jwtlens scan).");
  }
  const text = readTokenInput(input);
  const token = extractToken(text);
  if (!token) fail("no JWT found in the input (a token starts with 'eyJ').");
  return token;
}

function maybeVerify(decoded: ReturnType<typeof analyzeToken>["decoded"], opts: KeyOptions): VerifyResult | undefined {
  const key = readKeyInput(opts);
  if (!key) return undefined;
  if (decoded.error) return undefined;
  return verifyJwt(decoded, key);
}

cli
  .command("scan [input]", "Decode + security-lint a JWT (and verify if a key is given)")
  .option("-s, --secret <secret>", "HMAC shared secret for HS* verification")
  .option("-k, --key <file>", "Public key (PEM) for RS*/PS*/ES*/EdDSA verification")
  .option("-j, --jwk <file>", "JWK or JWKS file for verification")
  .option("--now <when>", "Evaluate timing against this ISO date / epoch (default: now)")
  .option("--config <file>", "Path to a config file")
  .option("--ignore <rules>", "Comma-separated rule ids to ignore")
  .option("--json <file>", "Write a JSON report to this path")
  .option("--md <file>", "Write a Markdown report to this path")
  .option("--min-score <n>", "CI gate: exit non-zero if the score is below this")
  .option("--quiet", "Hide the findings list")
  .example("  echo $TOKEN | jwtlens scan")
  .example("  jwtlens scan token.txt --key public.pem")
  .example('  jwtlens scan "$TOKEN" --secret "my-hmac-secret" --min-score 80')
  .action((input: string | undefined, opts: CommonKeyOpts & { config?: string; ignore?: string; json?: string; md?: string; minScore?: string; quiet?: boolean }) => {
    try {
      const token = resolveToken(input);
      const config: Config = loadConfig(opts.config);
      if (opts.ignore) config.ignore = [...config.ignore, ...opts.ignore.split(",").map((s) => s.trim()).filter(Boolean)];
      const now = parseNow(opts.now);

      const analysis = analyzeToken(token, config, now);
      const verification = maybeVerify(analysis.decoded, opts);
      const report = buildReport(analysis, { version: pkg.version, generatedAt: new Date().toISOString() }, verification);

      printReport(report, now, Boolean(opts.quiet));

      if (opts.json) {
        writeFileSync(resolve(opts.json), toJSON(report));
        console.log(pc.dim(`\nWrote JSON report → ${opts.json}`));
      }
      if (opts.md) {
        writeFileSync(resolve(opts.md), toMarkdown(report));
        console.log(pc.dim(`Wrote Markdown report → ${opts.md}`));
      }

      const minScore = opts.minScore !== undefined ? Number(opts.minScore) : config.minScore;
      if (analysis.decoded.error) process.exit(1);
      if (verification && !verification.valid) process.exit(1);
      if (report.summary.score < minScore) {
        console.error(`\n${pc.red("jwtlens:")} score ${report.summary.score} is below the minimum ${minScore}.`);
        process.exit(1);
      }
    } catch (e) {
      fail((e as Error).message);
    }
  });

cli
  .command("verify [input]", "Verify a JWT signature offline (exit 0 valid, 1 invalid)")
  .option("-s, --secret <secret>", "HMAC shared secret for HS*")
  .option("-k, --key <file>", "Public key (PEM)")
  .option("-j, --jwk <file>", "JWK or JWKS file")
  .example("  jwtlens verify token.txt --key public.pem")
  .example('  echo $TOKEN | jwtlens verify --secret "$SECRET"')
  .action((input: string | undefined, opts: KeyOptions) => {
    try {
      const token = resolveToken(input);
      const { decoded } = analyzeToken(token, DEFAULT_CONFIG, 0);
      if (decoded.error) fail(decoded.error);
      const key = readKeyInput(opts);
      if (!key) fail("provide a key: --secret, --key <pem>, or --jwk <file>.");
      const result = verifyJwt(decoded, key);
      if (result.valid) {
        console.log(`${pc.green("✓ verified")} ${pc.dim(`(${result.alg}) — ${result.reason}`)}`);
        process.exit(0);
      }
      console.error(`${pc.red("✗ not verified")} ${pc.dim(`(${result.alg}) — ${result.reason}`)}`);
      process.exit(1);
    } catch (e) {
      fail((e as Error).message);
    }
  });

cli
  .command("report <input>", "Render a saved JSON report as Markdown")
  .option("--md <file>", "Write Markdown to this path instead of stdout")
  .action((input: string, opts: { md?: string }) => {
    try {
      const report = JSON.parse(readFileSync(resolve(input), "utf8")) as Report;
      const md = toMarkdown(report);
      if (opts.md) {
        writeFileSync(resolve(opts.md), md);
        console.log(`Wrote ${opts.md}`);
      } else {
        process.stdout.write(md);
      }
    } catch (e) {
      fail((e as Error).message);
    }
  });

cli
  .command("init", "Write a jwtlens.config.json with the defaults")
  .option("--force", "Overwrite an existing config")
  .action((opts: { force?: boolean }) => {
    const file = resolve("jwtlens.config.json");
    if (existsSync(file) && !opts.force) {
      console.error(`${pc.red("jwtlens:")} jwtlens.config.json already exists (use --force).`);
      process.exit(1);
    }
    writeFileSync(file, JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n");
    console.log("Created jwtlens.config.json");
  });

cli.help();
cli.version(pkg.version);
cli.parse();

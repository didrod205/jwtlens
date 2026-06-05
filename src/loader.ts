/** Read the token and key material from arguments, files, or stdin (Node). */

import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import type { KeyInput } from "./verify.js";

function isFile(p: string): boolean {
  try {
    return existsSync(p) && statSync(p).isFile();
  } catch {
    return false;
  }
}

/** The raw text that contains the token: a file's contents, the arg itself, or stdin. */
export function readTokenInput(positional?: string): string {
  if (positional) {
    return isFile(resolve(positional)) ? readFileSync(resolve(positional), "utf8") : positional;
  }
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

export interface KeyOptions {
  secret?: string;
  key?: string;
  jwk?: string;
}

/** Build a {@link KeyInput} from CLI flags, reading key files as needed. */
export function readKeyInput(opts: KeyOptions): KeyInput | undefined {
  if (opts.secret !== undefined) return { secret: opts.secret };
  if (opts.key) {
    const path = resolve(opts.key);
    if (!isFile(path)) throw new Error(`key file not found: ${opts.key}`);
    return { pem: readFileSync(path, "utf8") };
  }
  if (opts.jwk) {
    const path = resolve(opts.jwk);
    if (!isFile(path)) throw new Error(`jwk file not found: ${opts.jwk}`);
    try {
      return { jwk: JSON.parse(readFileSync(path, "utf8")) as unknown };
    } catch (e) {
      throw new Error(`invalid JWK JSON in ${opts.jwk}: ${(e as Error).message}`);
    }
  }
  return undefined;
}

/** Parse a --now value (ISO date or epoch seconds) into epoch seconds. */
export function parseNow(value: string | undefined): number {
  if (!value) return Math.floor(Date.now() / 1000);
  const asNum = Number(value);
  if (Number.isFinite(asNum)) return Math.floor(asNum);
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) throw new Error(`invalid --now value: ${value}`);
  return Math.floor(ms / 1000);
}

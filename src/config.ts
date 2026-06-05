/** Configuration defaults, parsing, and resolution (pure — no file I/O). */

import type { Config } from "./types.js";

export const DEFAULT_CONFIG: Config = {
  ignore: [],
  maxLifetimeSeconds: 86_400, // 24h
  clockSkewSeconds: 60,
  minScore: 0,
};

export const CONFIG_FILENAMES = ["jwtlens.config.json", ".jwtlensrc.json", ".jwtlensrc"];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function mergeConfig(base: Config, override: Partial<Config>): Config {
  const out = { ...base } as unknown as Record<string, unknown>;
  for (const [k, value] of Object.entries(override ?? {})) {
    if (value !== undefined) out[k] = value;
  }
  return out as unknown as Config;
}

export function parseConfig(json: string, label = "config"): Config {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch (e) {
    throw new Error(`invalid ${label}: ${(e as Error).message}`);
  }
  if (!isPlainObject(data)) throw new Error(`invalid ${label}: must be a JSON object`);
  return mergeConfig(DEFAULT_CONFIG, data as Partial<Config>);
}

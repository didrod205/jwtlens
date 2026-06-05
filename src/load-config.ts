/** File-system config loading (Node-only — kept out of the library core). */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CONFIG_FILENAMES, DEFAULT_CONFIG, parseConfig } from "./config.js";
import type { Config } from "./types.js";

export function loadConfig(explicitPath?: string, cwd: string = process.cwd()): Config {
  let file: string | undefined = explicitPath ? resolve(cwd, explicitPath) : undefined;
  if (!file) {
    for (const name of CONFIG_FILENAMES) {
      const candidate = resolve(cwd, name);
      if (existsSync(candidate)) {
        file = candidate;
        break;
      }
    }
  }
  if (!file) return DEFAULT_CONFIG;
  if (!existsSync(file)) throw new Error(`config file not found: ${file}`);
  return parseConfig(readFileSync(file, "utf8"), `config ${file}`);
}

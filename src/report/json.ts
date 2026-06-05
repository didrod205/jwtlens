/** Serialize a Report as pretty JSON. */

import type { Report } from "../types.js";

export function toJSON(report: Report): string {
  return JSON.stringify(report, null, 2) + "\n";
}

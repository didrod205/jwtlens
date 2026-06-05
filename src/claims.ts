/** Helpers for reading registered claims and formatting time. */

export function numClaim(payload: Record<string, unknown>, key: string): number | undefined {
  const v = payload[key];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export function hasClaim(payload: Record<string, unknown>, key: string): boolean {
  const v = payload[key];
  if (v === undefined || v === null) return false;
  if (typeof v === "string") return v.length > 0;
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

/** Format a non-negative duration in seconds as e.g. "2d 3h", "45m", "30s". */
export function formatDuration(seconds: number): string {
  const s = Math.abs(Math.round(seconds));
  if (s < 60) return `${s}s`;
  const units: [number, string][] = [
    [86400, "d"],
    [3600, "h"],
    [60, "m"],
    [1, "s"],
  ];
  const parts: string[] = [];
  let rem = s;
  for (const [size, label] of units) {
    if (rem >= size) {
      parts.push(`${Math.floor(rem / size)}${label}`);
      rem %= size;
    }
    if (parts.length === 2) break;
  }
  return parts.join(" ") || "0s";
}

/** "expired 3h ago" / "in 55m" relative to `now` (both in epoch seconds). */
export function relativeTime(epochSeconds: number, now: number): string {
  const delta = epochSeconds - now;
  return delta >= 0 ? `in ${formatDuration(delta)}` : `${formatDuration(delta)} ago`;
}

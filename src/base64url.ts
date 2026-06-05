/**
 * Dependency-free base64url codec that works in Node, Deno, Bun and the browser
 * (uses the global `atob`/`btoa` + `TextDecoder`/`TextEncoder`). JWT parts are
 * base64url with no padding.
 */

function pad(b64: string): string {
  const rem = b64.length % 4;
  return rem === 0 ? b64 : b64 + "=".repeat(4 - rem);
}

export function base64UrlToBytes(input: string): Uint8Array {
  const b64 = pad(input.replace(/-/g, "+").replace(/_/g, "/"));
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function base64UrlToString(input: string): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(base64UrlToBytes(input));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

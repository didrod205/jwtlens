/**
 * Pull a JWT out of whatever you paste: a bare token, an `Authorization: Bearer`
 * header, or a log line with the token embedded. A JWS compact token always
 * starts `eyJ` (base64url of `{"`), which makes it easy to find precisely.
 */

const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;

export function extractToken(text: string): string | null {
  const trimmed = text.trim();
  // A bare token (possibly prefixed with "Bearer ").
  const bare = trimmed.replace(/^bearer\s+/i, "");
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(bare)) return bare;

  // Otherwise find the first token-shaped substring.
  const m = JWT_RE.exec(trimmed);
  return m ? m[0] : null;
}

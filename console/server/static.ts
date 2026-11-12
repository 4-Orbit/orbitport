import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, join, normalize, sep } from "node:path";
import type { ServerResponse } from "node:http";

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

/** Serves a file from the built client. Returns false if there is no such file. */
export function serveStatic(dir: string, pathname: string, res: ServerResponse): boolean {
  const decoded = decodeSafe(pathname);
  if (decoded === null) return false;
  const relative = decoded === "/" ? "index.html" : decoded.replace(/^\/+/, "");
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir).replace(/[\\/]?$/, sep))) return false; // no path traversal
  if (!existsSync(file) || !statSync(file).isFile()) return false;

  res.writeHead(200, {
    "Content-Type": TYPES[extname(file)] ?? "application/octet-stream",
    "X-Content-Type-Options": "nosniff",
    // The editor (CodeMirror) injects its theme as inline <style>, so styles
    // allow 'unsafe-inline'; scripts stay 'self' only.
    "Content-Security-Policy":
      "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "Referrer-Policy": "no-referrer",
  });
  res.end(readFileSync(file));
  return true;
}

function decodeSafe(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

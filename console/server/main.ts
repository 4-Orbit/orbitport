import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "./app.ts";

const here = dirname(fileURLToPath(import.meta.url));
const DIST_DIR = resolve(here, "../dist");

const gatewayUrl = (process.env.ORBITPORT_URL ?? "http://127.0.0.1:8080").replace(/\/+$/, "");
const tokenFile = process.env.ORBITPORT_CONSOLE_PAT_FILE ?? resolve(here, "../../.4orbit/tokens/operator.pat");
// 127.0.0.1 by default. The container sets 0.0.0.0 and compose publishes the
// port on host loopback only.
const host = process.env.CONSOLE_HOST ?? "127.0.0.1";
const port = Number(process.env.CONSOLE_PORT ?? 4317);
const extraHosts = (process.env.CONSOLE_ALLOWED_HOSTS ?? "").split(",").map((h) => h.trim()).filter(Boolean);

const staticDir = existsSync(DIST_DIR) ? DIST_DIR : undefined;

createApp({ gatewayUrl, tokenFile, staticDir, allowedHosts: ["127.0.0.1", "localhost", "[::1]", ...extraHosts] }).listen(port, host, () => {
  console.log(`Orbitport console: http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${port}${staticDir ? "" : "  (API only: no build in dist/, use npm run dev)"}`);
  console.log(`Gateway: ${gatewayUrl}`);
  console.log(`Operator token file: ${tokenFile}${existsSync(tokenFile) ? "" : "  (missing: run make 4orbit-seed)"}`);
});

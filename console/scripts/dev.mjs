// `npm run dev`: the API server (restarts on change) and the Vite dev server,
// which proxies /api to it. Ctrl+C stops both.
import { spawn } from "node:child_process";

const children = [
  spawn(process.execPath, ["--import", "tsx", "--watch", "server/main.ts"], { stdio: "inherit" }),
  spawn("npx", ["vite"], { stdio: "inherit" }),
];

function stop(code = 0) {
  for (const child of children) child.kill("SIGTERM");
  process.exit(code);
}

process.on("SIGINT", () => stop());
process.on("SIGTERM", () => stop());
for (const child of children) child.on("exit", (code) => stop(code ?? 0));

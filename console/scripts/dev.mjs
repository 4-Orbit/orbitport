// `npm run dev`: the API server (restarts on change) and the Vite dev server,
// which proxies /api to it. Ctrl+C stops both.
//
// If the console port is taken (usually by the console container from
// `make 4orbit`), the dev API server uses the next free port instead of
// failing, and Vite proxies to it, so your server changes are what you see.
import { spawn } from "node:child_process";
import { createServer } from "node:net";

const free = (port) =>
  new Promise((resolve) => {
    const s = createServer()
      .once("error", () => resolve(false))
      .once("listening", () => s.close(() => resolve(true)))
      .listen(port, "127.0.0.1");
  });

const wanted = Number(process.env.CONSOLE_PORT ?? 4317);
let port = wanted;
while (!(await free(port))) port++;
if (port !== wanted) console.log(`Port ${wanted} is in use (probably the console container); the dev API server uses ${port} instead.`);

const env = { ...process.env, CONSOLE_PORT: String(port), CONSOLE_API_URL: `http://127.0.0.1:${port}` };
const children = [
  spawn(process.execPath, ["--import", "tsx", "--watch", "server/main.ts"], { stdio: "inherit", env }),
  spawn("npx", ["vite"], { stdio: "inherit", env }),
];

function stop(code = 0) {
  for (const child of children) child.kill("SIGTERM");
  process.exit(code);
}

process.on("SIGINT", () => stop());
process.on("SIGTERM", () => stop());
for (const child of children) child.on("exit", (code) => stop(code ?? 0));

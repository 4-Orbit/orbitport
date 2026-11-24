import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev only: the browser talks to Vite, which forwards /api to the console
// server (the BFF that holds the operator token). The client bundle never
// contains server code or credentials.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    // scripts/dev.mjs sets CONSOLE_API_URL when the dev API server moves port.
    proxy: { "/api": process.env.CONSOLE_API_URL ?? "http://127.0.0.1:4317" },
  },
  // CodeMirror makes the single admin bundle ~600 kB; that is fine here.
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 800 },
});

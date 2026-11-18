import { defineConfig, devices } from "@playwright/test";

/**
 * Browser checks against a running 4Orbit stack and console (not run by
 * `npm test` or CI, which have no stack): `make 4orbit-up && make
 * 4orbit-seed`, then `npm run e2e:browser`. CONSOLE_URL points at a console
 * other than the default http://127.0.0.1:4317.
 */
export default defineConfig({
  testDir: "e2e",
  timeout: 90_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.CONSOLE_URL ?? "http://127.0.0.1:4317",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});

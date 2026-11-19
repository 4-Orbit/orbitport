import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

/**
 * The whole loop on a live stack: a real DENY is explained, "Grant this"
 * opens the rule form pre-filled, the saved and activated rule makes the
 * KMS allow the same request, and "Run it for real" agrees with Simulate
 * at both ends. The active version is restored afterwards.
 *
 * Decrypt is used because no default rule grants it and "Run it for real"
 * sends a dummy ciphertext: Cedar decides on the key, and after the ALLOW
 * the KMS refuses the sample, so no key is ever used for real data.
 */

async function rpc<T>(request: APIRequestContext, method: string, params: Record<string, unknown> = {}): Promise<T> {
  const res = await request.post("/api/rpc", { data: { method, params } });
  const body = (await res.json()) as { result?: T; error?: { message: string } };
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result as T;
}

async function simulate(page: Page, action: string) {
  await page.goto("/#/simulate");
  await page.getByLabel("Evaluate against").selectOption("active");
  await page.getByLabel("Principal (agent id; empty = account)").fill("developer-agent");
  await page.getByLabel("Action").selectOption(action);
  await page.getByLabel("Resource (Key)").fill("dev-key");
  await page.getByRole("button", { name: "Evaluate", exact: true }).click();
}

let original = 0;

test.beforeAll(async ({ request }) => {
  const active = await rpc<{ exists: boolean; version?: { version: number; policies: string } }>(request, "policy.GetActive");
  test.skip(!active.exists, "needs an active policy version (make 4orbit-seed)");
  original = active.version!.version;
  const r = await rpc<{ results: { decision: string }[] }>(request, "policy.Simulate", {
    requests: [{ agentId: "developer-agent", action: "kms.Decrypt", resource: { type: "Key", id: "dev-key" } }],
  });
  test.skip(r.results[0].decision !== "DENY", "the active version already lets developer-agent decrypt dev-key");
});

test.afterAll(async ({ request }) => {
  if (original) await rpc(request, "policy.Activate", { version: original, force: true });
});

test("DENY → why → Grant this → activate → real ALLOW", async ({ page, request }) => {
  // 1. A real DENY, explained, and the KMS agrees.
  await simulate(page, "kms.Decrypt");
  const result = page.locator(".sim-result");
  await expect(result.locator(".big-decision")).toHaveText("DENY");
  await expect(result.locator(".explanation-headline")).toHaveText("No rule lets developer-agent decrypt with dev-key.");
  await result.getByRole("button", { name: "Run it for real" }).click();
  await expect(result.locator(".run-compare")).toContainText("The KMS agrees with the simulation: DENY");

  // 2. Grant this: the rule form opens on Policies, pre-filled.
  await result.getByRole("button", { name: "Grant this: let developer-agent decrypt dev-key…" }).click();
  await expect(page).toHaveURL(/#\/policies$/);
  const form = page.getByRole("form", { name: "New rule" });
  await expect(form).toContainText("developer-agent can decrypt with dev-key.");
  await form.getByRole("button", { name: "Add rule" }).click();
  await expect(page.locator(".toast")).toContainText("Added rule");

  // 3. Save it, then activate (forced: the stored tests may pin this cell).
  await page.getByLabel("Version message").fill("e2e: grant from an explanation");
  await page.getByRole("button", { name: "Save as new version" }).click();
  const saved = page.getByText(/Saved as version \d+/);
  await expect(saved).toBeVisible();
  const version = Number(/Saved as version (\d+)/.exec((await saved.textContent()) ?? "")![1]);
  const act = await rpc<{ activated: boolean }>(request, "policy.Activate", { version, force: true });
  expect(act.activated).toBe(true);

  // 4. The same request is now allowed, simulated and for real. The KMS
  //    caches the active version for about 5 seconds.
  await page.waitForTimeout(6_000);
  await simulate(page, "kms.Decrypt");
  await expect(result.locator(".big-decision")).toHaveText("ALLOW");
  await result.getByRole("button", { name: "Run it for real" }).click();
  const cmp = result.locator(".run-compare");
  await expect(cmp).toContainText(`The KMS agrees with the simulation: ALLOW under v${version}`);
  await expect(cmp).toContainText("allowed by policy; the KMS refused the sample request");
});

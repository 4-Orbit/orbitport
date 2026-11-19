import { expect, test } from "@playwright/test";

// "Save and activate" previews what changes before enforcing anything. This
// spec never changes enforcement: it cancels a real change, and activates a
// draft identical to the active version (which saves nothing and activates
// nothing).
test.use({ channel: process.env.PLAYWRIGHT_CHANNEL });

test("Save and activate previews changes and is a no-op for an unchanged draft", async ({ page, request }) => {
  const rpc = async <T,>(method: string, params: object = {}) => ((await (await request.post("/api/rpc", { data: { method, params } })).json()) as { result: T }).result;
  const active = await rpc<{ version?: { version: number } }>("policy.GetActive");
  test.skip(!active.version, "needs an active policy version (make 4orbit-seed)");
  const before = active.version!.version;
  const versionsBefore = (await rpc<{ versions: { version: number }[] }>("policy.ListVersions", { limit: 1 })).versions[0]?.version;

  await page.goto("/#/policies");
  await page.getByRole("button", { name: "Start from active", exact: true }).click();

  // A real change: preview it, then cancel.
  const agent = `e2e-activate-${Date.now().toString(36)}`;
  await page.getByLabel("New agent id").fill(agent);
  await page.getByRole("button", { name: "Add agent", exact: true }).click();
  await page.getByRole("button", { name: "+ Add rule", exact: true }).click();
  const form = page.getByRole("form", { name: "New rule", exact: true });
  await form.getByLabel("Who", { exact: true }).selectOption("agent");
  await form.getByLabel("Agent", { exact: true }).selectOption(agent);
  await form.getByRole("button", { name: "Any key", exact: true }).click();
  await form.getByRole("button", { name: "Add rule", exact: true }).click();
  await expect(page.getByText("VALID", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Save and activate…", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Save and activate this draft?" });
  await expect(dialog).toContainText(`replacing the active version v${before}`);
  await expect(dialog.locator("li", { hasText: agent }).first()).toContainText("kms.Encrypt");
  await expect(dialog).toContainText(/\d+ becomes? ALLOW/);
  expect(await page.locator("dialog.confirm-dialog").evaluate((d) => d.matches(":modal"))).toBe(true);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(dialog).toHaveCount(0);

  // An unchanged draft: activating it reports that nothing changed.
  await page.getByRole("button", { name: "Start from active", exact: true }).click();
  const confirmReplace = page.getByRole("button", { name: /Replace|Discard|Load/ });
  if (await confirmReplace.count()) await confirmReplace.first().click();
  await expect(page.getByRole("article", { name: `Rule ${agent}-encrypt-any-key` })).toHaveCount(0);
  await expect(page.getByText("VALID", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save and activate…", exact: true }).click();
  await expect(dialog).toContainText("no change");
  const go = dialog.getByRole("button", { name: "Save and activate", exact: true });
  test.skip((await dialog.getByRole("button", { name: "Save without activating" }).count()) > 0, "stored tests fail against the active version");
  await go.click();
  await expect(page.getByText(`identical to version ${before}`)).toBeVisible();
  await expect(page.getByText("already active. Nothing changed.")).toBeVisible();
  // The status strip and the header agree on the active version.
  await expect(page.locator(".topbar")).toContainText(`Active policy v${before}`);
  await expect(page.getByText(`Your draft matches the active version v${before}`)).toBeVisible();

  const after = await rpc<{ version?: { version: number } }>("policy.GetActive");
  expect(after.version!.version).toBe(before);
  expect((await rpc<{ versions: { version: number }[] }>("policy.ListVersions", { limit: 1 })).versions[0]?.version).toBe(versionsBefore);
});

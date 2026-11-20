import { expect, type Page, test } from "@playwright/test";

// Deleting an agent asks, in a modal, whether to delete the rules written for
// it. Edits only this fresh browser context's draft: never saves or activates.
test.use({ channel: process.env.PLAYWRIGHT_CHANNEL });

async function addAgentWithRule(page: Page, agent: string) {
  await page.getByLabel("New agent id").fill(agent);
  await page.getByRole("button", { name: "Add agent", exact: true }).click();
  await page.getByRole("button", { name: "+ Add rule", exact: true }).click();
  const form = page.getByRole("form", { name: "New rule", exact: true });
  await form.getByLabel("Who", { exact: true }).selectOption("agent");
  await form.getByLabel("Agent", { exact: true }).selectOption(agent);
  await form.getByRole("button", { name: "Any key", exact: true }).click();
  await form.getByRole("button", { name: "Add rule", exact: true }).click();
  const card = page.getByRole("article", { name: `Rule ${agent}-encrypt-any-key`, exact: true });
  await expect(card).toBeVisible();
  return card;
}

test("deleting an agent offers to delete its rules, in a blocking dialog", async ({ page }) => {
  await page.goto("/#/policies");
  await page.getByRole("button", { name: "Start from active", exact: true }).click();
  // A fresh id, so no rule in the active version already names it.
  const agent = `e2e-gone-${Date.now().toString(36)}`;
  const card = await addAgentWithRule(page, agent);

  await page.getByRole("button", { name: `Remove agent ${agent}`, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: `Delete agent ${agent}?` });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText(`${agent}-encrypt-any-key`);
  await expect(dialog).toContainText("registered again they grant it access immediately");
  // Modal: the page behind it can't be used until the dialog is answered.
  expect(await page.locator("dialog.confirm-dialog").evaluate((d) => d.matches(":modal"))).toBe(true);
  await expect(page.getByRole("button", { name: "+ Add rule", exact: true }).click({ timeout: 1500 })).rejects.toThrow();
  await expect(page.getByRole("form", { name: "New rule", exact: true })).toHaveCount(0);

  // Escape cancels: nothing changed.
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("button", { name: `Remove agent ${agent}`, exact: true })).toBeVisible();

  // Agent only: the rule stays, flagged.
  await page.getByRole("button", { name: `Remove agent ${agent}`, exact: true }).click();
  await dialog.getByRole("button", { name: "Delete agent only", exact: true }).click();
  await expect(page.getByRole("button", { name: `Remove agent ${agent}`, exact: true })).toHaveCount(0);
  await expect(card).toContainText("AGENT NOT REGISTERED");

  // Undo, then delete the agent with its rule: one step removes both.
  await page.locator(".toast").getByRole("button", { name: "Undo", exact: true }).click();
  await expect(card).not.toContainText("AGENT NOT REGISTERED");
  await page.getByRole("button", { name: `Remove agent ${agent}`, exact: true }).click();
  await dialog.getByRole("button", { name: "Delete agent and 1 rule", exact: true }).click();
  await expect(page.locator(".toast")).toContainText(`Deleted agent ${agent} and 1 rule`);
  await expect(card).toHaveCount(0);
  await expect(page.getByRole("button", { name: `Remove agent ${agent}`, exact: true })).toHaveCount(0);
});

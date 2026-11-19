import { expect, test } from "@playwright/test";

// Runs against a console with the GitHub service configured. Edits only this
// fresh browser context's draft: never saves, activates or creates an issue.
test.use({ channel: process.env.PLAYWRIGHT_CHANNEL });

test("create and edit a repository-scoped GitHub rule in plain language", async ({ page, request }) => {
  const response = await request.post("/api/rpc", { data: { method: "github.ListRepositories", params: {} } });
  const metadata = await response.json() as { result?: { repositories: string[] } };
  const repository = metadata.result?.repositories[0];
  test.skip(!repository, "requires a configured GitHub repository");
  await page.goto("/#/policies");
  await page.getByRole("button", { name: "Start from active", exact: true }).click();
  await page.getByRole("button", { name: "+ Add rule", exact: true }).click();
  let form = page.getByRole("form", { name: "New rule", exact: true });
  await form.getByLabel("Service", { exact: true }).selectOption("github");
  await form.getByLabel("Role", { exact: true }).selectOption("developer");
  await expect(form.getByRole("checkbox", { name: "Create issues", exact: true })).toBeChecked();
  await expect(form.getByRole("checkbox", { name: /Everything/ })).toHaveCount(0);
  await expect(form.getByRole("button", { name: "Add rule", exact: true })).toBeDisabled();
  await form.getByRole("checkbox", { name: repository!, exact: true }).check();
  await form.getByLabel("Rule name", { exact: true }).fill("github-builder-check");
  await expect(form.locator(".rule-sentence")).toHaveText(`Agents with the developer role can create issues in ${repository}.`);
  await form.getByRole("button", { name: "Show the Cedar this writes", exact: true }).click();
  await expect(form.locator(".cedar-preview")).toContainText(`Repository::"${repository}"`);
  await form.getByRole("button", { name: "Add rule", exact: true }).click();
  const card = page.getByRole("article", { name: "Rule github-builder-check", exact: true });
  await expect(card).not.toContainText("CUSTOM CEDAR");
  await card.getByRole("button", { name: "Edit", exact: true }).click();
  form = page.getByRole("form", { name: "Edit rule github-builder-check", exact: true });
  await expect(form.getByLabel("Service", { exact: true })).toHaveValue("github");
  await expect(form.getByRole("checkbox", { name: repository!, exact: true })).toBeChecked();
  await form.getByRole("button", { name: "Blocks", exact: true }).click();
  await form.getByRole("button", { name: "Update rule", exact: true }).click();
  await expect(card.locator(".rule-sentence")).toHaveText(`Agents with the developer role can never create issues in ${repository}.`);
});

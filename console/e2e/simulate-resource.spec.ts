import { expect, test } from "@playwright/test";

// The simulator's resource field follows the action's resource type: a key
// alias is never sent as a repository, or the reverse. Evaluates only; never
// saves, activates or calls the KMS or GitHub.
test.use({ channel: process.env.PLAYWRIGHT_CHANNEL });

test("switching between KMS and GitHub actions resets the resource", async ({ page, request }) => {
  const res = await request.post("/api/rpc", { data: { method: "github.ListRepositories", params: {} } });
  const repositories = ((await res.json()) as { result?: { repositories: string[] } }).result?.repositories ?? [];
  test.skip(repositories.length === 0, "requires a configured GitHub repository");

  await page.goto("/#/simulate");
  await page.getByLabel("Evaluate against").selectOption("active");
  await page.getByLabel("Principal", { exact: true }).selectOption("developer-agent");
  await page.getByLabel("Action").selectOption("kms.Encrypt");
  const key = page.getByLabel("Resource (key)", { exact: true });
  await key.selectOption("dev-key");
  await expect(page.getByLabel("Key tags override (k=v, …)")).toBeVisible();

  // KMS -> GitHub: a configured repository replaces dev-key; key tags go away.
  await page.getByLabel("Action").selectOption("github.issue.Create");
  const repo = page.getByLabel("Resource (repository)", { exact: true });
  await expect(repo).toHaveValue(repositories[0]);
  for (const r of repositories) await expect(repo.locator("option", { hasText: r })).toHaveCount(1);
  await expect(repo.locator("option", { hasText: "dev-key" })).toHaveCount(0);
  await expect(page.getByLabel("Key tags override (k=v, …)")).toHaveCount(0);
  await page.getByRole("button", { name: "Evaluate", exact: true }).click();
  await expect(page.locator(".sim-result")).toBeVisible();
  await expect(page.locator(".sim-result")).not.toContainText("malformed repository id");
  await expect(page.locator(".sim-result")).not.toContainText("EVALUATION ERROR");

  // Other… accepts an unlisted repository, and checks its format.
  await repo.selectOption({ label: "Other…" });
  const typed = page.getByLabel("Resource (repository): other value", { exact: true });
  await typed.fill("not-a-repo");
  await expect(page.getByRole("button", { name: "Evaluate", exact: true })).toBeDisabled();
  await typed.fill("someone/elsewhere");
  await expect(page.getByRole("button", { name: "Evaluate", exact: true })).toBeEnabled();

  // GitHub -> KMS: back to a key.
  await page.getByLabel("Action").selectOption("kms.Decrypt");
  await expect(page.getByLabel("Resource (key)", { exact: true })).toHaveValue("dev-key");
  await page.getByRole("button", { name: "Evaluate", exact: true }).click();
  await expect(page.locator(".sim-result")).not.toContainText("EVALUATION ERROR");
});

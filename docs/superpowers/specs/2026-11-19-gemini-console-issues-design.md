# Gemini issue creation in the main console

## Intent

An operator gives a registered Orbitport agent one task on the main GitHub page. Gemini proposes one issue title and body; the console sends that proposal through the existing `Runner.createGithubIssue` path. The gateway and `plugin-github` enforce the active Cedar policy and write the normal Activity decision. One submission can attempt at most one GitHub issue.

## Scope and constraints

- Use the existing console container and the Gemini Interactions API. No autonomous loop, separate runner container, MCP tool, or new GitHub credential.
- A single `GEMINI_API_KEY` is supplied to the console at runtime from `.4orbit.env`. It stays server-side; the browser never sees it. Without a key, manual issue creation continues to work and the Gemini endpoint reports unavailable.
- The operator chooses an agent and repository from the existing page. The server validates those values and a task of at most 4,000 characters. The model may return only a title and body; it cannot choose an agent or repository.
- The operator confirms that a Gemini proposal may create an issue before submitting. In LIVE mode, the UI says this can create a real GitHub issue. The server requires confirmation for every Gemini submission.
- The console validates one tool call and the existing issue request limits before calling `Runner.createGithubIssue`. It calls Gemini with `store: false`, a 30-second timeout, and at most one retry on HTTP 503. The GitHub operation is never retried.
- Gemini HTTP failures return their status and standard reason to the browser. Network failures and timeouts get distinct safe errors. Prompt, API key, PAT, and provider response body do not enter Activity or server logs.
- The UI displays the generated issue title and the same decision, issue link, and Activity link as manual creation.

## Approaches considered

1. **Console one-shot flow (chosen):** Smallest change; reuses the signed agent PAT and enforced GitHub workflow already in the stack.
2. **Standalone demo in Docker:** Packages the prior prototype but keeps its separate local identity and Cedar policy.
3. **Autonomous runner container:** Supports long-running work and stop controls, but requires MCP GitHub tools, run lifecycle, and stronger sandboxing.

## Verification

Tests use fake Gemini and gateway transports: valid proposal calls `github.issue.Create` once with an agent PAT; DENY makes no GitHub provider call; invalid/multiple tool calls and provider errors make no gateway issue call; confirmation and missing key block before Gemini; the API key and prompt never appear in responses or Activity. Console typecheck and build pass. No live GitHub issue is created during automated tests.

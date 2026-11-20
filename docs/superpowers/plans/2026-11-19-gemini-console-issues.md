# Gemini Console Issues Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the main console turn one Gemini task into at most one Cedar-governed GitHub issue.

**Architecture:** A console-server Gemini adapter proposes a title and body. A new console endpoint validates the operator request, calls the adapter, then calls the existing `Runner.createGithubIssue`, which mints an agent PAT and uses `plugin-github`. The GitHub page submits the task and shows the existing issue result UI.

**Tech Stack:** Node 24/TypeScript console BFF, React/Vite, Docker Compose, native fetch, Node test runner.

**Spec:** `docs/superpowers/specs/2026-11-19-gemini-console-issues-design.md`

## Global Constraints

- Do not put `GEMINI_API_KEY`, an operator PAT, an agent PAT, or the GitHub App key in browser code or responses.
- Use `store: false`; permit one Gemini 503 retry, no GitHub creation retry.
- Do not change gateway or plugin authorization; use `Runner.createGithubIssue`.
- Keep missing-key behavior explicit and keep manual GitHub issue creation functional.

## Review Focus

- Forged agent/repository fields in Gemini tool arguments must not change the operator-selected identity or resource; test strict tool arguments.
- Provider 503 and timeout must not trigger more than one GitHub issue attempt; test adapter and endpoint call counts.
- Missing real-mode confirmation must block before Gemini; test the endpoint.
- Invalid title/body must block before issuing an agent PAT; test the endpoint.
- Gemini request content and secrets must not appear in Activity, API errors, or logs; test safe response and request payload.

---

### Task 1: Server-side Gemini proposal adapter

**Files:** Create `console/server/gemini.ts`; test in `console/test/gemini.test.ts`.

**Interfaces:** `createGeminiClient({ apiKey, model?, fetchImpl?, waitImpl? }).proposeIssue({ prompt, repository }): Promise<{ title, body }>`; export a typed error with an HTTP status when the provider supplies one.

- [ ] Write tests for one `create_issue` function call, `store: false`, strict title/body bounds, HTTP errors, a single 503 retry, and no retry on 401.
- [ ] Run `node --import tsx --test test/gemini.test.ts` and confirm the new tests fail.
- [ ] Implement the adapter using `POST https://generativelanguage.googleapis.com/v1beta/interactions`, default model `gemini-3.5-flash-lite`, 30-second timeout, and fixed safe errors.
- [ ] Run the focused test and confirm it passes.

### Task 2: Console endpoint and runtime configuration

**Files:** Modify `console/server/app.ts`, `4orbit.compose.yaml`, `.4orbit.env.example`; test in `console/test/app.test.ts`.

**Interfaces:** `POST /api/github/gemini-issues` accepts exactly `{agentId, repository, prompt, confirmCreate:true}` and returns `{result, proposal}`; uses `Runner.createGithubIssue` after proposal validation.

- [ ] Write endpoint tests for missing key, confirmation, malformed request, provider failure, and one successful request using a fake Gemini transport and fake gateway transport.
- [ ] Run `node --import tsx --test test/app.test.ts` and confirm failure.
- [ ] Add the endpoint with the existing Host/JSON checks and rate limit, inject Gemini only when `GEMINI_API_KEY` exists, and pass the runtime env through the console Compose service.
- [ ] Run the focused tests and confirm they pass.

### Task 3: GitHub page and documentation

**Files:** Modify `console/src/pages/GithubPage.tsx`, `console/src/api.ts`, `console/src/types.ts` if needed, `docs/4orbit/github.md`, `console/README.md`; test in `console/test/github.test.ts` and existing browser e2e if practical.

**Interfaces:** `api.createGeminiGithubIssue(agentId, repository, prompt, confirmCreate)` calls the new endpoint; the GitHub page shows a task field and a LIVE confirmation, then displays the proposal title and existing result component.

- [ ] Add API and page tests for enabled, unavailable, and LIVE confirmation states.
- [ ] Run the focused tests and confirm failure.
- [ ] Implement the task form and documentation; keep manual creation unchanged.
- [ ] Run focused tests, `npm test`, `npm run typecheck`, and `npm run build`.
- [ ] Review the diff for secret exposure, run `git diff --check`, and commit the feature.

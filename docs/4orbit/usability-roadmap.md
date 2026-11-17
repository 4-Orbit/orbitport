# Console usability roadmap (items 1–15)

The plan for the next round of console work, after steps 1–3 (undo and confirmations, plain-language rules, Draft → Saved → Active, in-console help). Each item lists the problem, the change, the backend and frontend work, how we'll know it's done, and a size: **S** ≈ ½–1 day, **M** ≈ 2–3 days, **L** ≈ 4–5 days.

Ground rules carried over:
- Saved versions stay immutable. Anything editable is information *about* a version, and edits to it are recorded.
- Every decision shown in the console comes from the enforcement engine (`pkg/core/authz`). No second implementation in the browser.
- Each item ships with tests, including at least one Go or console unit test and an e2e or browser check for user-visible flows.
- Run the baseline usability test (`usability-test.md`) **before Milestone A** and again after Milestones A and C.

---

## Milestone A: understand and fix access (≈ 2 weeks)

### 1. "Why was this denied?" + Grant this (L)
- **Problem:** a DENY says "default deny" and nothing more. Users can't tell what's missing (usability task 2).
- **Change:** on any DENY (Activity detail, Access cell, Simulate result), explain it:
  - *Blocked by* `no-prod-for-developers` (a forbid matched);
  - *Expired*: `developer-encrypt-demo-key` stopped applying on Jan 15 2027;
  - *Closest rule*: `security-rotate-dev-key` would allow this, but requires the **security** role and developer-agent has **developer**;
  - *No rule mentions* kms.Rotate on dev-key.

  Each explanation ends with **Grant this…**, which opens the rule form pre-filled (who, action, key), or **Edit the blocking rule**.
- **Backend:** `authz.Explain(compiled, req, now)`. For each tenant permit whose effect could apply, report which parts of its scope and condition fail (principal, action, resource, time, tag). Also report matched forbids and expired grants. Return the explanation from a new `policy.Explain` method, and include it in `policy.Simulate` results for DENYs.
- **Frontend:** an `Explanation` component used by Activity, Access and Simulate, with a deep link into the rule form.
- **Done when:** each of the four DENY kinds above produces the right explanation (Go table test). In the usability test, task 2 is answered correctly in under 30 s by ≥ 90 % of participants.

### 2. Per-agent pages (L)
- **Problem:** "what can this agent do?" means reading a matrix and cross-referencing roles (usability task 5).
- **Change:** a page per agent (`#/agents/<id>`):
  - its roles, as chips you can add or remove;
  - a plain-language list of what it can do on each key, each line naming the rule and role that grants it;
  - what expires soon;
  - its recent Activity;
  - actions: **Grant…**, **Copy permissions to a new agent**, **Mint token**, **Remove agent** (with the usual confirmation and undo).
- **Backend:** none new. It uses Matrix, Explain (1) and ListAudit filtered by agent.
- **Frontend:** a new page, plus links to it from every agent name in the console.
- **Done when:** usability task 5 succeeds for ≥ 80 % without help, and "Copy permissions" produces an agent with identical matrix rows (unit test against Matrix).

### 3. Version names, descriptions, hiding, and "what changed since the version before" (M)
- **Problem:** versions are just numbers plus a message frozen at save time. Duplicates and experiments clutter the list, and you can't see what each version changed.
- **Change:**
  - **Editable:** a name (≤ 60 characters, shown everywhere as "v5 · Q4 baseline"), a description, and *hidden* and *pinned* flags. Contents are never editable.
  - **Automatic:** where the version came from (template, a draft based on vN, a forced copy), who saved it, and a one-line summary of the change from the previous version ("+1 rule · −0 · 1 decision changes").
  - A **"Show hidden versions"** toggle. The active version can't be hidden.
  - A history of information edits (who changed what, and when).
- **Backend:**
  - Store the editable information at `tenants/<t>/versioninfo/<n>`, separate from the immutable `versions/<n>`.
  - Add `policy.UpdateVersionInfo {version, name?, description?, hidden?, pinned?}` (a policy.Write action), and audit it.
  - `SaveDraft` records where the version came from (`source`).
  - `ListVersions` returns the information plus the change summary, computed once at save time and stored.
- **Frontend:** edit in place on Versions, the name shown in the status strip, header and Activity, and filter chips.
- **Done when:** renaming and hiding survive a restart of `plugin-policy` (KV-backed test); hidden versions are excluded from the list but still activatable from the toggle; the change summary matches `policy.Diff` (test).

### 4. Save & activate from the Policies page (S)
- **Problem:** activating requires leaving the editor for the Versions tab.
- **Change:** after a save, the status strip offers **Activate v9 now**. It runs the tests in place and shows pass or fail. If they fail, it lists the failing cases with "Open Tests" and "Activate anyway…".
- **Backend:** none (uses `policy.Activate`).
- **Done when:** a new rule can go from draft to enforced without leaving Policies, and the e2e check passes through the same path.

---

## Milestone B: change safely (≈ 1.5 weeks)

### 5. Try a change in shadow mode first (L)
- **Problem:** shadow mode applies to the whole KMS and is an environment setting, so you can't trial a single version on real traffic.
- **Change:** on Versions, **Try in shadow** for a saved version. The KMS keeps enforcing the active version but also evaluates the shadow one. Activity marks disagreements ("ALLOWED now · **would be DENIED** under v9"). A banner counts disagreements, with **Make v9 active** or **Stop trial**. The trial ends automatically after a set time (15 min, 1 h or 24 h).
- **Backend:**
  - The policy plugin stores `{shadowVersion, until}` per tenant, and `GetActive` returns it too.
  - The KMS plugin's `guard` evaluates both versions and adds `shadowDecision` and `shadowPolicies` to the audit event (enforcing only the active decision).
  - New methods: `policy.StartShadow` and `policy.StopShadow`.
- **Done when:**
  - a KMS unit test confirms the shadow decision never affects enforcement;
  - e2e: a trial of v2 (developers may rotate) shows a disagreement when the developer rotates and the KMS still denies;
  - the trial ends by itself.

### 6. Warn before removing access that's in use (M)
- **Problem:** deleting a rule or role can silently break an agent that relies on it.
- **Change:** in the delete confirmations (rule, role, agent membership) and in the "What changes vs active?" list, add usage from audit: "deployment-agent used this permission **14×** in the last 24 h (last 3 min ago)."
- **Backend:** `policy.Usage {requests: [...]}` aggregates allowed decisions from the audit ring by (principal, action, resource) and determining policy, with counts and the last-seen time.
- **Done when:** removing a rule that granted traffic in the last 24 h shows a count matching the audit (unit test on the aggregation).

### 7. Readable tests (M)
- **Problem:** the 98 generated cases are named after the matrix, and failures read like data.
- **Change:**
  - optional test groups with names ("Developers never touch prod");
  - failures in sentences: "**Developers must never rotate keys**: now ALLOWED by `developer-rotate-dev-key` (v9)";
  - after a change, the console offers to turn each changed decision into a test ("Lock this in?");
  - "Only failures" becomes the default view after a failed run.
- **Backend:** `TestCase` gains an optional `group` and `why` (schema-compatible).
- **Done when:** a failed activation shows sentences, and saving offered tests from a diff round-trips (unit test).

### 8. Export and import (M)
- **Problem:** dev OpenBao loses everything on teardown, and there's no way to share or review a policy set.
- **Change:**
  - **Export** downloads one JSON bundle (`orbitport-policy-bundle-v1`) containing the policies, agents and roles, tests, and version information.
  - **Import** loads a bundle into the draft, never saving directly. It validates first and shows the diff against active, then asks whether to replace the tests (the same opt-in pattern as the template).
- **Backend:** none. It's built from existing methods. Optionally add `scripts/4orbit/export.sh` and `import.sh` for the command line.
- **Done when:** export → `make 4orbit-down && make 4orbit` → import → save → activate restores identical decisions (e2e).

---

## Milestone C: polish and scale (≈ 1.5 weeks)

### 9. Agents & roles editor that scales (S)
- **Problem:** the agents × roles checkbox grid overflows past about three roles.
- **Change:** one row per agent with role chips (× removes; "+ role" adds through autocomplete), plus a separate Roles list showing member counts. This merges into the agent pages (item 2) where possible.
- **Done when:** 20 roles and 50 agents render without horizontal scrolling at 1280 px, and all the existing confirmation and undo behavior is unchanged.

### 10. One message area (S)
- **Problem:** the intro, status strip, status banner and undo toast can all be visible at once.
- **Change:** one message area below the strip: the newest message, with any action (Undo, Replace tests, Go to v1), and older messages folded into a small "2 earlier" list. Intros stay collapsible.
- **Done when:** no more than one message is visible at a time, and every action that existed is still reachable.

### 11. An Access grid that scales (M)
- **Problem:** one table per agent with every key and action becomes a wall.
- **Change:**
  - filters for role, agent, key tag and action group;
  - **Only show differences** (vs active, when viewing a draft or version);
  - a summary row per agent ("allowed on 3 of 12 keys");
  - collapsed agents by default when there are more than 10;
  - server-side matrix paging (see 15).
- **Done when:** 50 agents × 100 keys load in under 1 s, and "differences only" equals `policy.Diff`.

### 12. First-visit tour (S)
- **Change:** five steps, shown once, repeatable from Help: Policies (plain language) → the status strip → Save → Versions/Activate → Activity. It uses the same glossary text.
- **Depends on:** the usability test results. Only add it if participants still get lost after items 1–4.
- **Done when:** the tour can be dismissed, never reappears unasked, and works with the keyboard.

### 13. Tabs organized around tasks (M)
- **Change:** the navigation becomes **Overview** (active version, recent denials, what expires soon, trials running) · **Agents** (pages from item 2) · **Rules** (today's Policies) · **Activity** · **History** (Versions + Tests). Simulate becomes a panel available everywhere ("Ask Cedar"). Old `#/…` links redirect.
- **Depends on:** items 1, 2 and 5. Do it last in this milestone.
- **Done when:** the usability-test path lengths (tabs visited per task) drop compared with the baseline.

### 14. Accessibility pass (M)
- **Change:**
  - a logical keyboard order through the rule form;
  - focus moves into a form when it opens and back to its trigger when it closes;
  - Escape closes forms and confirmations;
  - `aria-live` on the status strip and messages;
  - grid cells with full labels (already partly done);
  - colour contrast checked to WCAG AA;
  - reduced motion respected;
  - one screen-reader pass (VoiceOver).
- **Done when:** axe-core reports no serious issues on each page (automated in the Playwright smoke test), and the five usability tasks can be completed keyboard-only.

---

## 15. Pagination (cross-cutting, M; do the first part in Milestone A)

> **Status: done** on `fix/version-paging`, with three differences from the plan below. The rule form's key picker searches the keys already loaded (up to 2,000) rather than the server. `includeHidden` waits for item 3. The Access page went further than paging: it lists agents with per-agent counts and shows one agent's keys at a time (the "summary row per agent" part of item 11).

| List | Today | Change |
|---|---|---|
| **Versions** | Server returns the newest 100; older versions are invisible, and the duplicate check only sees those 100 | **Bug, fix first.** `ListVersions {cursor?, limit≤100, includeHidden?}` returns `{versions, nextCursor}`. The duplicate check stores a content hash per version at `tenants/<t>/hashes/<sha256>` → version, so it's one lookup instead of a scan. The console shows "Load older versions". |
| **Activity** | Newest 200 of the 2000 in memory; filters apply only to those | `ListAudit {cursor?, limit≤200, filters}` filters **before** paging over the whole store, returning `nextCursor` (the newest-first ring index). The console uses infinite scroll with "Load older", and polling prepends newer events without losing your scroll position. |
| **Keys** | `ListKeys` stops at 200 and sets `truncated`, which the console ignores | `ListKeys {cursor?, limit≤200}` → `{keys, nextCursor}` (KV LIST is already sorted, so the cursor is the last key ID). The rule form's key picker searches the server ("type to find keys"), and the Access grid uses key paging. |
| **Tests** | Up to 2000 rows rendered | Client-side: page size 100, failures first after a run, a search box. The data is already in the browser. |
| **Rules** | All cards rendered | Client-side: render in windows of 50, with filtering already available. Server-side isn't needed: the text is capped at 256 KB. |
| **Access matrix** | Every agent × key × action in one response | `Matrix {agents?, keyCursor?, keyLimit}`, so the console asks for one agent's rows, or one page of keys at a time (with item 11). |

**Shared conventions:** cursors are opaque strings; `limit` has a server maximum; every list response says whether more exists; and the console never silently drops items (show "showing 200 of 1,240 · Load more").

**Done when:**
- Go tests page through 250 versions and 1,000 audit events with filters, and through 450 keys;
- the duplicate check finds a match older than 100 versions;
- a console test confirms "Load more" appends without duplicates.

---

## Order and estimate

| Sprint | Items | Why this order |
|---|---|---|
| 0 (2–3 days) | Baseline usability test · **15 (versions paging + hash duplicate check, keys `truncated` handling)** | Measure first; fix the silent truncation bugs before adding features on top of them |
| 1 | 3 (version naming) · 4 (save & activate) · 10 (one message area) · 9 (roles editor) | Small, high-visibility wins that make versions understandable |
| 2 | 1 (why denied + Grant this) · rest of 15 (activity and keys paging) | The biggest comprehension gain; Explain is reused by item 2 |
| 3 | 2 (agent pages) · 6 (usage warnings) · second usability round | Agent-centric view, then measure |
| 4 | 5 (shadow trials) · 7 (readable tests) · 8 (export/import) | Safer rollout and durability |
| 5 | 11 (Access at scale) · 13 (task-based tabs) · 14 (accessibility) · 12 (tour, only if still needed) · third usability round | Polish once the structure has settled |

Roughly 5–6 weeks for one developer, or about half that with two working in parallel on the backend (Explain, shadow, paging) and frontend (pages, editor, polish).

## Open decisions

1. **Version names: unique or not?** Recommendation: not unique, but warn on duplicates. Versions are always identified by number.
2. **Can hidden versions be activated?** Recommendation: yes, from the toggle. Hiding is only for tidiness.
3. **How long can a shadow trial run?** Recommendation: a 24 h maximum, with one trial per tenant at a time.
4. **Durable audit** (needed for item 6's 24 h usage and long Activity history): set `ORBITPORT_POLICY_AUDIT_DIR` on a volume now, and use a real store later (open question 6 in TODO.md).
5. **Who reads the plain-language view?** If non-engineers are the main audience, default new users to Plain language and keep Cedar behind the switch (as it is today). If engineers are, consider remembering the last mode per user instead of per browser.

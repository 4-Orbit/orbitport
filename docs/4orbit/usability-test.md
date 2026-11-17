# Console usability test (baseline and follow-ups)

A 30-minute moderated test of the policy playground with people who didn't build it. Run it now as a baseline, then after each usability phase, so the capstone can show measured improvement rather than opinion.

## Who and how many

- 3–5 participants per round. Five find most of the large problems. Vary them: at least one person with no security background, and at least one who has never seen Cedar.
- One moderator who only reads the tasks and asks "what are you thinking?", and one note-taker. Don't help. If someone is stuck for 3 minutes, mark the task failed, show them the answer, and move on.
- Record the screen and audio with consent. Use a fresh stack: `make 4orbit-down && make 4orbit`, wait for the seed, open http://127.0.0.1:4317, and clear the browser's site data for 127.0.0.1:4317.

## Script

Read aloud:

> You're the operator for a company whose AI agents use encryption keys. Agents can only do what the rules on this console allow. I'll give you five tasks. Please think out loud. We're testing the console, not you, so if something is confusing, that's what we want to find.

Give no other introduction: no tour, no glossary.

| # | Task (read exactly) | Success means | Time limit |
|---|---|---|---|
| 1 | "The deployment agent needs to **sign** things with **prod-key**. Make that possible, but don't make it live yet." | A rule or Cedar policy granting `deployment-agent` (or the `deployment` role) `kms.Sign` on `prod-key`, saved as a new version and not activated | 6 min |
| 2 | "The developer agent tried to **rotate dev-key** and was refused. Why?" | Says, in their own words, that nothing allows developers to rotate keys (only security can) | 4 min |
| 3 | "Make the developer's access to **demo-key** end **next Friday at 5 pm UTC**." | The developer `demo-key` rule's expiry changed to that time, in the draft | 5 min |
| 4 | "You just made a change you didn't mean to. **Undo it.**" (First have them delete the `security` role, or any rule.) | The deleted item is back, using Undo or the toast | 2 min |
| 5 | "A new agent, **audit-agent**, should be able to do **exactly what the security agent can**." | `audit-agent` exists and has the `security` role (or equivalent rules) | 5 min |

Afterwards, ask:

1. "On a scale of 1–5, how confident are you that the changes you made do what you intended?"
2. "What was the most confusing moment?"
3. "Did you ever want to see or write the underlying code? When?"
4. The ten System Usability Scale (SUS) questions, on paper.

## What to record per participant

| Measure | How |
|---|---|
| Task success | Pass, pass with a hint, or fail, per task |
| Time on task | Stopwatch, from reading the task to "done" |
| Errors | Wrong rule or key or agent saved, unintended access, an activation they didn't mean |
| Mode used | Plain language, Cedar, or both (for task 1 and task 3) |
| Path | Which tabs they visited, in order |
| Quotes | Verbatim moments of confusion |
| Confidence (1–5) and SUS score | From the questionnaire |

Keep the results in a table, one row per participant, with one sheet per round. Summarize as: success rate per task, median time per task, total errors, mean SUS.

## Targets

| Measure | Baseline (Cedar only, before rule cards) | Target after Phase 1 | Target after Phase 2 |
|---|---|---|---|
| Task 1 success without typing Cedar | expected low | ≥ 80 % | ≥ 90 % |
| Task 2 correct answer | — | ≥ 60 % | ≥ 90 %, in under 30 s ("why denied") |
| Task 3 success | — | ≥ 80 % | ≥ 90 % |
| Task 4 success | 0 % (no undo existed) | 100 % | 100 % |
| Task 5 success | — | ≥ 60 % | ≥ 80 % (agent pages, "copy permissions") |
| Mean SUS | — | ≥ 68 (average) | ≥ 75 |
| Unintended access granted | — | 0 | 0 |

The baseline round should use the console from before this change (`feat/fourorbit-migration`) to measure where we started. Follow-up rounds use the current branch with the **Plain language** view as the default.

## After each round

1. Group the problems by page and give each a severity: 3 = blocked the task, 2 = slowed it significantly, 1 = cosmetic.
2. Fix everything rated 3 before the next round, and record what changed.
3. Re-run with **new** participants. Someone who has already done the tasks learns them.

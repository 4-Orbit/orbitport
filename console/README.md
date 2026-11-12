# Orbitport console (4Orbit policy playground)

An operator console for agent authorization, ported from 4Orbit GUI v1 (`4-Orbit/4orbit/web`) and extended into a policy playground. It has a Vite + React client and a small Node server (BFF) that holds the operator PAT.

| Tab | What it does |
|---|---|
| Activity | Live decision audit with filters, plus a detail panel with "Replay in simulator" |
| Access | Agents × keys × KMS actions for the active version, the draft or any saved version, optionally at a simulated time |
| Policies | Cedar editor (CodeMirror 6) with validation as you type, an agents-and-roles editor, snippets, the decision diff against active, and save as a new version |
| Simulate | Ask Cedar about any request, with time travel; save the result as a test case |
| Tests | The saved expectations: run against any source, edit, save |
| Versions | History, decision and text diffs, activation gated by the test suite, rollback |
| Agents | Registered agents and short-lived agent tokens (shown once) |

## Security model

- The server binds `127.0.0.1` by default. In Docker it binds `0.0.0.0`, but compose publishes it on host loopback only.
- Requests whose `Host` isn't loopback get a 403, which blocks DNS rebinding. Add hosts with `CONSOLE_ALLOWED_HOSTS`.
- `/api/rpc` accepts only JSON (so a cross-site form can't post to it) and only allowlisted methods (`server/app.ts`). The KMS crypto methods aren't allowlisted.
- The operator PAT is read from `ORBITPORT_CONSOLE_PAT_FILE` on every call and is never included in a response; error paths redact it. The only token that reaches the browser is an agent token that the operator explicitly mints, shown once.
- CSP: scripts are `'self'` only. Inline styles are allowed because CodeMirror needs them.

## Run

With the stack running (`make 4orbit-up` from the repo root), the `console` container already serves http://127.0.0.1:4317. For development:

```sh
docker stop console          # free :4317
npm ci
npm run dev                  # client on http://127.0.0.1:5173, API on :4317
```

| Env | Default |
|---|---|
| `ORBITPORT_URL` | `http://127.0.0.1:8080` |
| `ORBITPORT_CONSOLE_PAT_FILE` | `../.4orbit/tokens/operator.pat` |
| `CONSOLE_HOST` / `CONSOLE_PORT` | `127.0.0.1` / `4317` |
| `CONSOLE_ALLOWED_HOSTS` | — (comma-separated extra Host names) |

## Test

```sh
npm test            # BFF: allowlist, Host check, token never returned, error mapping, static
npm run typecheck
npm run build
```

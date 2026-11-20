# Orbitport console (4Orbit policy playground)

An operator console for agent authorization, ported from 4Orbit GUI v1 (`4-Orbit/4orbit/web`) and extended into a policy playground. It has a Vite + React client and a small Node server (BFF) that holds the operator PAT.

What each tab does, and a five-minute walkthrough, are in [`DEPLOY.md` §7](../DEPLOY.md#7-the-console-and-policy-playground).

## Security model

- The server binds `127.0.0.1` by default. In Docker it binds `0.0.0.0`, but compose publishes it on host loopback only.
- Requests whose `Host` isn't loopback get a 403, which blocks DNS rebinding. Add hosts with `CONSOLE_ALLOWED_HOSTS`.
- `/api/rpc` accepts only JSON (so a cross-site form can't post to it) and only allowlisted methods (`server/app.ts`). The KMS crypto methods aren't allowlisted; **Run it for real** (`/api/run`) and GitHub issue creation (`/api/github/issues`) have their own endpoints, which act with a short-lived agent token the server mints and never with the operator token.
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
| `GEMINI_API_KEY` | — (optional; enables Gemini issue creation) |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` |

## Test

```sh
npm test            # BFF: allowlist, Host check, token never returned, error mapping, static
npm run typecheck
npm run build
npm run e2e:browser # against a running stack: DENY → why → Grant this → activate → real ALLOW
```

## GitHub issues

The **GitHub** tab creates issues as an agent through the same Cedar flow, mock by default. With `GEMINI_API_KEY` set in `.4orbit.env`, the same tab accepts a task for Gemini to turn into one issue. Setup, the real GitHub App and the request flow are in [`docs/4orbit/github.md`](../docs/4orbit/github.md).

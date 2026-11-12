import { useEffect, useState } from "react";
import { api } from "../api.ts";
import type { IssuedToken, Version } from "../types.ts";
import { entityIds, rolesOf } from "../draft.tsx";

const TTLS = [
  { label: "5 minutes", seconds: 300 },
  { label: "15 minutes", seconds: 900 },
  { label: "1 hour", seconds: 3600 },
  { label: "4 hours", seconds: 14400 },
  { label: "24 hours", seconds: 86400 },
];

/** Registered agents and short-lived agent PATs. A token is shown once and never stored. */
export function AgentsPage() {
  const [active, setActive] = useState<Version | null | undefined>(undefined);
  const [agent, setAgent] = useState("");
  const [ttl, setTtl] = useState(3600);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .active()
      .then((a) => {
        setActive(a.version ?? null);
        const first = a.version ? entityIds(a.version.entities, "Agent")[0] : "";
        setAgent((cur) => cur || first || "");
      })
      .catch((e: Error) => setError(e.message));
    // Forget a displayed token when leaving the page.
    return () => setIssued(null);
  }, []);

  async function mint() {
    setError(null);
    setCopied(false);
    try {
      setIssued(await api.issueAgentToken(agent, ttl));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const agents = active ? entityIds(active.entities, "Agent") : [];

  return (
    <>
      <section className="panel">
        <header className="panel-head">
          <h2>Registered agents</h2>
          <span className="muted small">{active ? `from active version ${active.version}` : "no active version"}</span>
        </header>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Agent</th>
                <th>Roles</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a}>
                  <td className="mono">{a}</td>
                  <td className="mono">{rolesOf(active!.entities, a).join(", ") || <span className="muted">none</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {active !== undefined && agents.length === 0 && <p className="empty">No agents in the active version. Register agents on the Policies page and activate.</p>}
        </div>
      </section>

      <section className="panel">
        <header className="panel-head">
          <h2>Mint an agent token</h2>
          <span className="muted small">a PAT with a signed agent_id claim; the KMS enforces your policies for it</span>
        </header>
        <form
          className="panel-body row wrap"
          onSubmit={(e) => {
            e.preventDefault();
            void mint();
          }}
        >
          <label className="field inline">
            <span>Agent</span>
            <select value={agent} onChange={(e) => setAgent(e.target.value)}>
              {agents.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </label>
          <label className="field inline">
            <span>Lifetime</span>
            <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
              {TTLS.map((t) => (
                <option key={t.seconds} value={t.seconds}>
                  {t.label}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="button primary" disabled={!agent}>
            Mint token
          </button>
        </form>
        {error && <div className="banner banner-error inline-banner">{error}</div>}
        {issued && (
          <div className="panel-body stack token-box">
            <p>
              <strong>Copy this token now.</strong> It is not stored and will not be shown again. It expires {new Date(issued.expiresAt * 1000).toISOString()} and carries roles: {issued.roles.join(", ") || "none"}.
            </p>
            <div className="row">
              <code className="token mono">{issued.token}</code>
              <button
                type="button"
                className="button"
                onClick={() => {
                  void navigator.clipboard?.writeText(issued.token).then(() => setCopied(true));
                }}
              >
                {copied ? "Copied" : "Copy"}
              </button>
              <button type="button" className="button" onClick={() => setIssued(null)}>
                Hide
              </button>
            </div>
            <h3>Use it from an MCP client (kms-mcp)</h3>
            <p className="muted small">Save the token to a file (mode 600), then point the launcher at it:</p>
            <pre>{`{
  "mcpServers": {
    "kms-${issued.agentId}": {
      "command": "/ABSOLUTE/PATH/orbitport/mcp/scripts/kms-mcp-from-file.sh",
      "env": {
        "ORBITPORT_URL": "http://127.0.0.1:8080",
        "ORBITPORT_PAT_FILE": "/ABSOLUTE/PATH/${issued.agentId}.pat"
      }
    }
  }
}`}</pre>
            <h3>Or call the API directly</h3>
            <pre>{`curl -s http://127.0.0.1:8080/api/v1/rpc \\
  -H 'Content-Type: application/json' \\
  -H "Authorization: Bearer $(cat ${issued.agentId}.pat)" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"kms.Encrypt","params":{"KeyId":"kms:dev-key","Plaintext":"aGVsbG8="}}'`}</pre>
          </div>
        )}
      </section>
    </>
  );
}

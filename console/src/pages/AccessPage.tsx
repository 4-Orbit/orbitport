import { Intro, Term } from "../components/Help.tsx";
import { useEffect, useMemo, useState } from "react";
import { api, keyResources } from "../api.ts";
import { useDraft } from "../draft.tsx";
import type { MatrixResult, PrincipalSummary } from "../types.ts";
import { MatrixGrid } from "../components/MatrixGrid.tsx";
import { SourcePicker, TimeTravel, toEpoch, toSource, type SourceChoice } from "../components/SourcePicker.tsx";
import { SimTimeBadge } from "../components/Badges.tsx";
import { useVersions, useKeys } from "./shared.ts";
import { Pager } from "../components/Pager.tsx";

const KEYS_PER_PAGE = 25;
const AGENTS_PER_PAGE = 25;

const short = (action: string) => action.replace(/^kms\./, "").replace(/Key$/, "");
const label = (principal: string) => principal || "(account)";

/**
 * Who can do what, one agent at a time: a summary list of agents on the left
 * (how many keys each can use), and the selected agent's keys on the right,
 * by default only the keys it can access. Each pager pages exactly one list.
 */
export function AccessPage() {
  const draft = useDraft();
  const versions = useVersions();
  const keys = useKeys();
  const [choice, setChoice] = useState<SourceChoice>("active");
  const [when, setWhen] = useState("");
  const [includeAccount, setIncludeAccount] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [summary, setSummary] = useState<MatrixResult | null>(null);
  const [agentOffset, setAgentOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);

  const [detail, setDetail] = useState<MatrixResult | null>(null);
  const [onlyAllowed, setOnlyAllowed] = useState(true);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [keyOffset, setKeyOffset] = useState(0);

  const base = useMemo(
    () => ({ source: toSource(choice, draft), keys: keyResources(keys.data ?? []), includeAccount, at: toEpoch(when) }),
    // The draft is read at evaluation time; re-evaluate when its text changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [choice, when, includeAccount, keys.data, draft.policies, draft.entities],
  );

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  // Left: one summary row per agent, counted over every key.
  useEffect(() => {
    let cancelled = false;
    api
      .matrix({ ...base, summary: true, agentOffset, agentLimit: AGENTS_PER_PAGE })
      .then((m) => {
        if (cancelled) return;
        setSummary(m);
        setError(null);
        const list = m.summary ?? [];
        setSelected((cur) => (cur !== null && list.some((s) => s.principal === cur) ? cur : (list[0]?.principal ?? null)));
      })
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [base, agentOffset]);

  // Right: the selected agent's keys.
  useEffect(() => {
    if (selected === null) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    api
      .matrix({ ...base, agents: [selected], onlyAllowed, keySearch: debouncedSearch || undefined, keyOffset, keyLimit: KEYS_PER_PAGE })
      .then((m) => !cancelled && (setDetail(m), setError(null)))
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [base, selected, onlyAllowed, debouncedSearch, keyOffset]);

  // A new source, agent or filter starts the key list at its first page.
  useEffect(() => setKeyOffset(0), [base, selected, onlyAllowed, debouncedSearch]);
  useEffect(() => setAgentOffset(0), [choice, includeAccount]);

  const rows = summary?.summary ?? [];
  const current = rows.find((r) => r.principal === selected) ?? null;

  return (
    <>
      <Intro page="access" title="Access: who can do what">
        Pick an <Term k="agent" /> on the left to see exactly which keys it can use and for what, worked out from the rules. By default only keys it can access are listed. Pick
        “Editor draft” to preview unsaved changes, or a simulated time to see what changes after an expiry. Click a cell to see which rule decided.
      </Intro>
      <section className="panel toolbar">
        <SourcePicker value={choice} onChange={setChoice} versions={versions} />
        <TimeTravel value={when} onChange={setWhen} />
        <label className="field inline checkbox">
          <input type="checkbox" checked={includeAccount} onChange={(e) => setIncludeAccount(e.target.checked)} />
          <span>Include account principal</span>
        </label>
        {summary && <span className="muted small">source: {summary.source}</span>}
        {summary?.simulatedTime && <SimTimeBadge at={summary.at} />}
      </section>
      {error && <div className="banner banner-error inline-banner">{error}</div>}
      {keys.more && (
        <div className="banner banner-ok inline-banner">
          This tenant has more than {keys.data?.length} keys; counts cover the first {keys.data?.length} plus any key a rule names.
        </div>
      )}

      {summary && summary.totalPrincipals === 0 ? (
        <section className="panel empty-state">
          <h2>{summary.source === "draft" ? "Your draft" : summary.source.startsWith("v") ? `Version ${summary.source.slice(1)}` : "This policy set"} has no agents</h2>
          <p>
            It declares no agents, so every agent token would be denied under it.
            {!includeAccount && " Tick “Include account principal” to see what account tokens can do."}
          </p>
          <p className="muted small">
            Agents are declared under <strong>Agents & roles</strong> on the <a href="#/policies">Policies</a> page. To compare, pick “Active version” above.
          </p>
        </section>
      ) : (
        <div className="access-layout">
          <section className="panel agent-list" aria-label="Agents">
            <header className="panel-head">
              <h2>Agents</h2>
              <span className="muted small">{summary ? `${summary.totalPrincipals} · ${summary.totalKeys} keys` : "…"}</span>
            </header>
            <ul>
              {rows.map((r) => (
                <li key={r.principal}>
                  <AgentRow row={r} totalKeys={summary?.totalKeys ?? 0} selected={r.principal === selected} onSelect={() => setSelected(r.principal)} />
                </li>
              ))}
            </ul>
            {summary && (
              <div className="agent-list-pager">
                <Pager label="Agents" offset={summary.agentOffset} pageSize={AGENTS_PER_PAGE} total={summary.totalPrincipals} onChange={setAgentOffset} />
              </div>
            )}
          </section>

          <section className="agent-detail" aria-label={selected !== null ? `Access for ${label(selected)}` : "Access"}>
            {current && (
              <div className="panel agent-detail-head">
                <div>
                  <h2 className="mono">{label(current.principal)}</h2>
                  <p className="muted small">
                    {current.principal === "" ? "account-level credential (platform.owner): full access to this tenant" : current.roles.length ? `roles: ${current.roles.join(", ")}` : "no roles"}
                    {" · "}can use <strong>{current.allowedKeys}</strong> of {summary?.totalKeys} keys
                  </p>
                </div>
                <div className="row">
                  <label className="field inline checkbox">
                    <input type="checkbox" checked={onlyAllowed} onChange={(e) => setOnlyAllowed(e.target.checked)} />
                    <span>Only keys this agent can access</span>
                  </label>
                  <input aria-label="Find a key" placeholder="find a key…" value={search} onChange={(e) => setSearch(e.target.value)} />
                </div>
              </div>
            )}
            {detail && current && detail.totalKeys === 0 && (
              <section className="panel empty-state">
                <p>
                  {debouncedSearch
                    ? `No ${onlyAllowed ? "accessible " : ""}keys match “${debouncedSearch}”.`
                    : `${label(current.principal)} can't use any key under ${detail.source}. Every request it makes is denied.`}
                </p>
                {onlyAllowed && (
                  <button type="button" className="button small" onClick={() => setOnlyAllowed(false)}>
                    Show all keys
                  </button>
                )}
              </section>
            )}
            {detail && detail.totalKeys > 0 && (
              <>
                <MatrixGrid matrix={detail} hideHeader />
                <div className="panel pager-bar">
                  <span className="muted small">{onlyAllowed ? "Keys this agent can access" : "All keys"}</span>
                  <Pager label="Keys" offset={detail.keyOffset} pageSize={KEYS_PER_PAGE} total={detail.totalKeys} onChange={setKeyOffset} />
                  {detail.totalKeys <= KEYS_PER_PAGE && (
                    <span className="muted small">
                      {detail.totalKeys} key{detail.totalKeys === 1 ? "" : "s"}
                    </span>
                  )}
                </div>
              </>
            )}
          </section>
        </div>
      )}
      <p className="muted small note">
        Keys come from the KMS (with their tags) plus any key a rule names. Decisions use the same Cedar engine the KMS plugin enforces with.
      </p>
    </>
  );
}

function AgentRow({ row, totalKeys, selected, onSelect }: { row: PrincipalSummary; totalKeys: number; selected: boolean; onSelect: () => void }) {
  const actions = Object.entries(row.byAction)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
  return (
    <button type="button" className={`agent-row${selected ? " selected" : ""}`} aria-pressed={selected} onClick={onSelect}>
      <span className="agent-row-name mono">{label(row.principal)}</span>
      <span className="agent-row-roles muted small">{row.principal === "" ? "account token" : row.roles.join(", ") || "no roles"}</span>
      <span className="agent-row-count">
        <strong>{row.allowedKeys}</strong>
        <span className="muted small"> / {totalKeys} keys</span>
      </span>
      <span className="agent-row-actions">
        {actions.length === 0 ? (
          <span className="muted small">no access</span>
        ) : (
          actions.slice(0, 4).map(([a, n]) => (
            <span key={a} className="chip small">
              {short(a)} {n}
            </span>
          ))
        )}
        {actions.length > 4 && <span className="muted small">+{actions.length - 4}</span>}
      </span>
    </button>
  );
}

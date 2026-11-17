import { useEffect, useState } from "react";
import { api } from "../api.ts";
import { useDraft } from "../draft.tsx";
import type { Decision, TestCase, TestReport } from "../types.ts";
import { DecisionBadge, PolicyChips } from "../components/Badges.tsx";
import { SourcePicker, toSource, type SourceChoice } from "../components/SourcePicker.tsx";
import { useVersions } from "./shared.ts";

/** The tenant's saved expectations. Activation refuses a version that fails any. */
export function TestsPage() {
  const draft = useDraft();
  const versions = useVersions();
  const [tests, setTests] = useState<TestCase[] | null>(null);
  const [dirty, setDirty] = useState(false);
  const [choice, setChoice] = useState<SourceChoice>("draft");
  const [report, setReport] = useState<TestReport | null>(null);
  const [onlyFailures, setOnlyFailures] = useState(false);
  const [status, setStatus] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [newCase, setNewCase] = useState<TestCase>({ name: "", agentId: "", action: "kms.Encrypt", resource: { type: "Key", id: "" }, expect: "DENY" });

  useEffect(() => {
    api.tests().then((r) => setTests(r.tests)).catch((e: Error) => setStatus({ tone: "error", text: e.message }));
  }, []);

  async function runAll() {
    try {
      // Unsaved edits are run as given, so you can try them before saving.
      setReport(await api.runTests(toSource(choice, draft), dirty ? (tests ?? []) : undefined));
      setStatus(null);
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  async function save() {
    try {
      const r = await api.putTests(tests ?? []);
      setDirty(false);
      setStatus({ tone: "ok", text: `Saved ${r.count} test cases.` });
    } catch (e) {
      setStatus({ tone: "error", text: (e as Error).message });
    }
  }

  const edit = (next: TestCase[]) => {
    setTests(next);
    setDirty(true);
  };

  const resultByName = new Map(report?.results.map((r) => [r.name, r]));
  const shown = (tests ?? []).filter((t) => !onlyFailures || resultByName.get(t.name)?.pass === false);

  return (
    <>
      <section className="panel toolbar">
        <SourcePicker value={choice} onChange={setChoice} versions={versions} />
        <button type="button" className="button primary" onClick={() => void runAll()}>
          Run all
        </button>
        <button type="button" className="button" disabled={!dirty} onClick={() => void save()}>
          Save suite
        </button>
        <label className="field inline checkbox">
          <input type="checkbox" checked={onlyFailures} onChange={(e) => setOnlyFailures(e.target.checked)} />
          <span>Only failures</span>
        </label>
        {report && (
          <span className={`badge decision ${report.failed ? "decision-deny" : "decision-allow"}`}>
            {report.passed}/{report.total} PASS
          </span>
        )}
        {dirty && <span className="muted small">unsaved changes</span>}
      </section>
      {status && <div className={`banner inline-banner ${status.tone === "error" ? "banner-error" : "banner-ok"}`}>{status.text}</div>}

      <section className="panel">
        <header className="panel-head">
          <h2>Add a case</h2>
          <span className="muted small">or use "Save as test case" in the simulator</span>
        </header>
        <form
          className="panel-body row wrap"
          onSubmit={(e) => {
            e.preventDefault();
            if (!newCase.resource.id || !newCase.action) return;
            const name = newCase.name || `${newCase.agentId || "(account)"} ${newCase.action} ${newCase.resource.id}`;
            edit([...(tests ?? []), { ...newCase, name, agentId: newCase.agentId || undefined }]);
            setNewCase({ ...newCase, name: "", resource: { type: "Key", id: "" } });
          }}
        >
          <input aria-label="Name" placeholder="name (optional)" value={newCase.name} onChange={(e) => setNewCase({ ...newCase, name: e.target.value })} />
          <input aria-label="Agent" placeholder="agent (empty = account)" value={newCase.agentId ?? ""} onChange={(e) => setNewCase({ ...newCase, agentId: e.target.value.trim() })} />
          <input aria-label="Action" placeholder="kms.Encrypt" value={newCase.action} onChange={(e) => setNewCase({ ...newCase, action: e.target.value.trim() })} />
          <input aria-label="Key" placeholder="key alias" value={newCase.resource.id} onChange={(e) => setNewCase({ ...newCase, resource: { type: "Key", id: e.target.value.trim() } })} />
          <select aria-label="Expect" value={newCase.expect} onChange={(e) => setNewCase({ ...newCase, expect: e.target.value as Decision })}>
            <option value="ALLOW">expect ALLOW</option>
            <option value="DENY">expect DENY</option>
          </select>
          <button type="submit" className="button">
            Add
          </button>
        </form>
      </section>

      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Agent</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Time</th>
                <th>Expect</th>
                <th>Actual</th>
                <th>Determined by</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {shown.map((t) => {
                const r = resultByName.get(t.name);
                const index = (tests ?? []).indexOf(t);
                return (
                  <tr key={`${index}-${t.name}`} className={r && !r.pass ? "row-fail" : undefined}>
                    <td>{t.name}</td>
                    <td className="mono">{t.agentId || "(account)"}</td>
                    <td className="mono">{t.action}</td>
                    <td className="mono">{t.resource.id}</td>
                    <td className="mono muted">{t.at ? new Date(t.at * 1000).toISOString().slice(0, 19) + "Z" : "now"}</td>
                    <td>
                      <DecisionBadge decision={t.expect} />
                    </td>
                    <td>{r ? <DecisionBadge decision={r.actual} /> : <span className="muted">—</span>}</td>
                    <td>{r && <PolicyChips ids={r.determiningPolicies} />}</td>
                    <td>
                      <button type="button" className="link-button" onClick={() => edit((tests ?? []).filter((_, i) => i !== index))}>
                        remove
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {tests && tests.length === 0 && <p className="empty">No test cases. Loading the 4Orbit template installs the 98-case permission matrix.</p>}
        </div>
      </section>
    </>
  );
}

import { useEffect, useState } from "react";
import { api, keyResources } from "../api.ts";
import { useDraft } from "../draft.tsx";
import type { MatrixResult } from "../types.ts";
import { MatrixGrid } from "../components/MatrixGrid.tsx";
import { SourcePicker, TimeTravel, toEpoch, toSource, type SourceChoice } from "../components/SourcePicker.tsx";
import { SimTimeBadge } from "../components/Badges.tsx";
import { useVersions, useKeys } from "./shared.ts";

/** The access matrix: every registered agent x key x KMS action. */
export function AccessPage() {
  const draft = useDraft();
  const versions = useVersions();
  const keys = useKeys();
  const [choice, setChoice] = useState<SourceChoice>("active");
  const [when, setWhen] = useState("");
  const [includeAccount, setIncludeAccount] = useState(false);
  const [matrix, setMatrix] = useState<MatrixResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .matrix({ source: toSource(choice, draft), keys: keyResources(keys.data ?? []), includeAccount, at: toEpoch(when) })
      .then((m) => !cancelled && (setMatrix(m), setError(null)))
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
    // The draft is read at evaluation time; re-evaluate when its text changes.
  }, [choice, when, includeAccount, keys.data, draft.policies, draft.entities]);

  return (
    <>
      <section className="panel toolbar">
        <SourcePicker value={choice} onChange={setChoice} versions={versions} />
        <TimeTravel value={when} onChange={setWhen} />
        <label className="field inline checkbox">
          <input type="checkbox" checked={includeAccount} onChange={(e) => setIncludeAccount(e.target.checked)} />
          <span>Include account principal</span>
        </label>
        {matrix && <span className="muted small">source: {matrix.source}</span>}
        {matrix?.simulatedTime && <SimTimeBadge at={matrix.at} />}
      </section>
      {error && <div className="banner banner-error inline-banner">{error}</div>}
      {matrix && matrix.principals.length === 0 && (
        <section className="panel empty-state">
          <h2>No agents registered</h2>
          <p>
            Agents are declared in the policy bundle's entity store. Add some on the <a href="#/policies">Policies</a> page or load the 4Orbit template.
          </p>
        </section>
      )}
      {matrix && matrix.principals.length > 0 && <MatrixGrid matrix={matrix} />}
      <p className="muted small note">
        Keys come from the KMS (with their tags) plus any key a policy names. Decisions use the same Cedar engine the KMS plugin enforces with.
      </p>
    </>
  );
}

import { useEffect, useState } from "react";
import { explainText, type ExplainedRequest, type Part } from "../explain.ts";
import type { Explanation } from "../types.ts";

function Parts({ parts }: { parts: Part[] }) {
  return (
    <>
      {parts.map((p, i) =>
        p.policy ? (
          <code key={i} className={`chip${p.text.startsWith("platform.") ? " chip-platform" : ""}`}>
            {p.text}
          </code>
        ) : p.strong ? (
          <strong key={i}>{p.text}</strong>
        ) : (
          <span key={i}>{p.text}</span>
        ),
      )}
    </>
  );
}

/** "Why was this denied?", in plain language, from the engine's explanation. */
export function ExplanationView({ explanation, request, note }: { explanation: Explanation; request: ExplainedRequest; note?: string }) {
  if (explanation.kind === "allowed") return null;
  const t = explainText(explanation, request);
  return (
    <div className="explanation" role="note" aria-label="Why this was denied">
      <p className="explanation-title">Why was this denied?</p>
      <p className="explanation-headline">
        <Parts parts={t.headline} />
      </p>
      {t.details.length > 0 && (
        <ul className="explanation-details">
          {t.details.map((line, i) => (
            <li key={i}>
              <Parts parts={line} />
            </li>
          ))}
        </ul>
      )}
      {note && <p className="muted small">{note}</p>}
    </div>
  );
}

/**
 * Loads an explanation when shown (Access cells, Activity details), so lists
 * never compute explanations in bulk. `load` changes identity when the
 * request changes, which reloads.
 */
export function LiveExplanation({ load, request, note }: { load: () => Promise<Explanation>; request: ExplainedRequest; note?: string }) {
  const [state, setState] = useState<{ e: Explanation | null; error: string | null }>({ e: null, error: null });
  useEffect(() => {
    let cancelled = false;
    setState({ e: null, error: null });
    load()
      .then((e) => !cancelled && setState({ e, error: null }))
      .catch((err: Error) => !cancelled && setState({ e: null, error: err.message }));
    return () => {
      cancelled = true;
    };
  }, [load]);
  if (state.error) return <p className="muted small">Couldn't explain this decision: {state.error}</p>;
  if (!state.e) return <p className="muted small">Working out why…</p>;
  return <ExplanationView explanation={state.e} request={request} note={note} />;
}

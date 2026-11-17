import { Term } from "./Help.tsx";

interface Props {
  /** Edited since loading or saving. */
  dirty: boolean;
  /** The saved version the draft equals or was loaded from; null = never saved. */
  base: number | null;
  active: number | null;
  /** False until the version list has loaded. */
  known: boolean;
  /** The draft validates. */
  valid: boolean;
  empty: boolean;
  /** Decisions that differ from the active version; null while checking. */
  changes: number | null;
}

type StepState = "current" | "done" | "todo";

/**
 * Draft → Saved version → Active, always visible on the Policies page, with
 * one sentence saying what that means for enforcement right now.
 */
export function DraftStatus({ dirty, base, active, known, valid, empty, changes }: Props) {
  const unsaved = dirty || base === null;
  const savedNotActive = !unsaved && base !== active;
  const live = !unsaved && base !== null && base === active;

  const steps: { label: React.ReactNode; value: string; state: StepState }[] = [
    { label: <Term k="draft">Draft</Term>, value: unsaved ? (empty ? "empty" : "unsaved edits") : `same as v${base}`, state: unsaved ? "current" : "done" },
    { label: <Term k="version">Saved version</Term>, value: unsaved ? "not saved" : `v${base}`, state: unsaved ? "todo" : savedNotActive ? "current" : "done" },
    { label: <Term k="active">Active</Term>, value: active ? `v${active}` : "none", state: live ? "current" : "todo" },
  ];

  const changed = changes === null ? "…" : `${changes} decision${changes === 1 ? "" : "s"}`;
  let message: React.ReactNode;
  if (!known) message = "Checking versions…";
  else if (!valid) message = "Your draft has errors. Fix them (they're marked on the rules or lines) before saving.";
  else if (unsaved && empty && active === null) message = "Nothing is active yet, so agents are denied everything. Add rules, save them as a version, then activate it.";
  else if (unsaved && changes === 0 && active !== null)
    message = (
      <>
        Your draft decides every request <strong>the same way</strong> as the active version v{active}. Saving only matters if you changed names, comments or wording.
      </>
    );
  else if (unsaved)
    message = (
      <>
        Your draft changes <strong>{changed}</strong> compared with what's enforced{active ? ` (v${active})` : ""}. Save it as a version to keep it. Nothing changes for agents until you
        activate it.
      </>
    );
  else if (savedNotActive)
    message = (
      <>
        Your draft is saved as <strong>v{base}</strong>, but it isn't active: the KMS still enforces {active ? <strong>v{active}</strong> : "no version (agents are denied everything)"}
        {changes !== null && changes > 0 ? ` (${changed} ${changes === 1 ? "differs" : "differ"})` : ""}. <a href="#/versions">Activate it on Versions</a> when you're ready.
      </>
    );
  else message = <>Your draft matches the active version <strong>v{active}</strong>. This is what the KMS enforces right now.</>;

  return (
    <section className={`draft-status${live ? " is-live" : ""}`} aria-label="Draft status">
      <ol className="ds-steps">
        {steps.map((s, i) => (
          <li key={i} className={`ds-step ds-${s.state}`}>
            <span className="ds-label">{s.label}</span>
            <span className="ds-value mono">{s.value}</span>
          </li>
        ))}
      </ol>
      <p className="ds-message">{message}</p>
    </section>
  );
}

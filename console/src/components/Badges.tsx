// Every badge carries its word, never color alone (carried over from GUI v1).
import type { AuditEvent, Decision } from "../types.ts";

export function DecisionBadge({ decision }: { decision: Decision }) {
  return <span className={`badge decision decision-${decision.toLowerCase()}`}>{decision}</span>;
}

export function KmsCalledBadge({ called }: { called: boolean }) {
  return <span className={`badge called called-${called ? "yes" : "no"}`}>{called ? "YES" : "NO"}</span>;
}

export function ModeBadge({ mode }: { mode: AuditEvent["mode"] }) {
  return (
    <span className={`badge mode mode-${mode === "shadow" ? "mock" : "real"}`} title={mode === "shadow" ? "Shadow mode: evaluated and audited, never blocked" : "Enforced: DENY blocks the KMS call"}>
      {mode === "shadow" ? "SHADOW" : "ENFORCE"}
    </span>
  );
}

export function KmsResultBadge({ ev }: { ev: AuditEvent }) {
  if (!ev.kmsCalled) return <span className="badge result result-none">—</span>;
  if (ev.kmsResult?.status === "SUCCESS") return <span className="badge result result-success">SUCCESS</span>;
  return <span className="badge result result-error" title={ev.kmsResult?.errorCode}>{`ERROR ${ev.kmsResult?.errorCode ?? ""}`.trim()}</span>;
}

export function SimTimeBadge({ at }: { at: number }) {
  return (
    <span className="badge sim-time" title="Evaluated at a simulated time; enforcement always uses the KMS plugin's clock">
      SIMULATED TIME {new Date(at * 1000).toISOString().replace(".000Z", "Z")}
    </span>
  );
}

export function PolicyChips({ ids }: { ids: string[] }) {
  if (ids.length === 0) return <span className="muted">default deny</span>;
  return (
    <span className="chips">
      {ids.map((id) => (
        <code key={id} className={`chip${id.startsWith("platform.") ? " chip-platform" : ""}`}>
          {id}
        </code>
      ))}
    </span>
  );
}

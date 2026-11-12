import type { AuditResult } from "../types.ts";

export function SummaryStrip({ summary, agents }: { summary: AuditResult["summary"]; agents: number }) {
  return (
    <dl className="summary">
      <Stat label="Decisions" value={summary.total} detail="retained window" />
      <Stat label="Cedar ALLOW" value={summary.allow} tone="allow" />
      <Stat label="Cedar DENY" value={summary.deny} tone="deny" />
      <Stat label="KMS calls" value={summary.kmsCalled} />
      <Stat label="Authz errors" value={summary.errors} tone={summary.errors > 0 ? "warn" : undefined} detail="fail-closed DENY" />
      <Stat label="Principals shown" value={agents} />
    </dl>
  );
}

function Stat({ label, value, detail, tone }: { label: string; value: number; detail?: string; tone?: "allow" | "deny" | "warn" }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ""}`}>
      <dt>{label}</dt>
      <dd>
        <span className="stat-value">{value}</span>
        {detail && <span className="stat-detail">{detail}</span>}
      </dd>
    </div>
  );
}

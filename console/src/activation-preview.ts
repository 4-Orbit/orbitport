/**
 * What "Save and activate" would change, worked out before anything is
 * enforced. policy.Diff covers KMS key decisions only, so GitHub issue
 * creation is compared here from two policy.Simulate runs.
 */
import type { CellChange, Decision, SimRequest } from "./types.ts";

export const ISSUE_ACTION = "github.issue.Create";

/** One request per agent and configured repository, in a stable order. */
export function issueRequests(agents: string[], repositories: string[]): SimRequest[] {
  return [...new Set(agents)].sort().flatMap((agentId) => repositories.map((id) => ({ agentId, action: ISSUE_ACTION, resource: { type: "Repository", id } })));
}

/** Requests whose decision differs between the two runs (same order as `requests`). */
export function decisionChanges(requests: SimRequest[], before: { decision: Decision }[], after: { decision: Decision; determiningPolicies: string[] }[]): CellChange[] {
  if (before.length !== requests.length || after.length !== requests.length) throw new Error("simulation returned a different number of results");
  return requests.flatMap((r, i) =>
    before[i].decision === after[i].decision
      ? []
      : [{ principal: r.agentId ?? "", action: r.action, resource: r.resource.id, before: before[i].decision, after: after[i].decision, afterPolicies: after[i].determiningPolicies }],
  );
}

/** "2 become ALLOW, 1 becomes DENY", or "" when nothing changes. */
export function changeSummary(changes: CellChange[]): string {
  const allow = changes.filter((c) => c.after === "ALLOW").length;
  const deny = changes.length - allow;
  const part = (n: number, d: Decision) => (n ? `${n} become${n === 1 ? "s" : ""} ${d}` : "");
  return [part(allow, "ALLOW"), part(deny, "DENY")].filter(Boolean).join(", ");
}

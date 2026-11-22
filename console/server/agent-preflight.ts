/**
 * Before a Gemini run: which GitHub tools could the active policy allow this
 * agent in this repository? One batched policy.Simulate answers it without
 * calling Gemini, so a run where nothing is allowed costs no tokens, and
 * Gemini is only offered tools that might work.
 *
 * Actions with trusted context are tried in the contexts an agent working
 * normally would meet: its own agent/<id>/ branch, an ordinary file, another
 * agent's pull request. This is a cost filter, never authorization: every
 * real call is still decided by enforcement, so a tool kept here can still
 * be denied, and a tool dropped here is one the policy denies even in its
 * best ordinary case.
 */
import type { SimRequest } from "../src/types.ts";

/** An agent id that isn't the run's agent, for "someone else's pull request". */
const OTHER = "another-agent";

export function preflightRequests(agentId: string, repository: string, methods: string[]): { method: string; request: SimRequest }[] {
  const own = `agent/${agentId}/task`;
  const theirs = `agent/${OTHER}/task`;
  type Context = NonNullable<SimRequest["context"]>;
  const contexts: Record<string, Context[]> = {
    "github.contents.Read": [{ path: "README.md" }, { path: "" }],
    "github.branch.Create": [{ branch: own, isDefaultBranch: false, branchAgent: agentId }],
    "github.commit.Create": [{ branch: own, isDefaultBranch: false, branchAgent: agentId, paths: ["README.md"], touchesWorkflows: false }],
    "github.pr.Create": [{ headBranch: own, baseBranch: "main", isDefaultBase: true, headAgent: agentId }],
    "github.pr.Review": ["COMMENT", "REQUEST_CHANGES", "APPROVE"].flatMap((event): Context[] => [
      { event, headBranch: theirs, headAgent: OTHER, authorIsApp: true },
      { event, headBranch: "feature", authorIsApp: false },
    ]),
    "github.pr.Merge": [{ headBranch: theirs, baseBranch: "main", isDefaultBase: true, headAgent: OTHER, humanApprovals: 1, mergeableState: "clean" }],
  };
  const resource = { type: "Repository", id: repository };
  return [...new Set(methods)].flatMap((method) =>
    (contexts[method] ?? [undefined]).map((context) => ({ method, request: { agentId, action: method, resource, ...(context && { context }) } })),
  );
}

/** Methods with at least one ALLOW; null when the results can't be read. */
export function allowedMethods(requests: { method: string }[], results: unknown): Set<string> | null {
  if (!Array.isArray(results) || results.length !== requests.length) return null;
  const out = new Set<string>();
  results.forEach((r, i) => {
    if ((r as { decision?: unknown } | null)?.decision === "ALLOW") out.add(requests[i].method);
  });
  return out;
}

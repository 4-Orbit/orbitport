/**
 * Plain-language help for a Gemini agent step that didn't succeed: what
 * happened, and what an operator can do about it.
 */
import type { AgentStep } from "./types.ts";

export interface StepHelp {
  title: string;
  meaning: string;
  fixes: string[];
}

/** Steps worth explaining: denied, refused, failed, or never sent. */
export const needsHelp = (s: AgentStep) => s.decision === "DENY" || !!s.error || (!!s.status && s.status !== "SUCCESS");

export function stepHelp(s: AgentStep, ctx: { repository: string; agentId: string }): StepHelp {
  const reason = s.reason ?? "";
  if (s.error && !s.decision) {
    return {
      title: "The call was never sent",
      meaning: `Gemini's arguments were rejected before reaching the gateway: ${s.error}. No policy decision was made and nothing happened in GitHub.`,
      fixes: ["Usually Gemini corrects itself on the next call.", "If it keeps happening, make the task more specific (exact file paths, branch names, pull request numbers)."],
    };
  }
  if (s.decision === "DENY") {
    return {
      title: "Denied by the active policy",
      meaning: `Cedar denied ${ctx.agentId} this request${s.determiningPolicies?.length ? `, decided by ${s.determiningPolicies.join(", ")}` : " because no rule allows it (default deny)"}. GitHub was not called.`,
      fixes: [
        "Open the audit link to see the exact request, its trusted context, and an explanation of why it was denied.",
        "Try the same request in Simulate to see which rule would change the outcome.",
        `If the agent should be allowed, add a rule in Policies for ${ctx.repository}, then save and activate it.`,
      ],
    };
  }
  if (/didn't issue a token with/.test(reason)) {
    return {
      title: "The GitHub App lacks a permission",
      meaning: "The policy allowed this, but GitHub refused to issue a token with the permission it needs, so nothing was written.",
      fixes: [
        "In the App's settings (Developer settings → GitHub Apps → Permissions), give it the permission named above.",
        "Then accept the new permissions on the installation: the org's Settings → Third-party Access → GitHub Apps → Configure → Review request. Until an org owner accepts, the installation keeps the old permissions.",
        `Check that the installation's repository access includes ${ctx.repository}.`,
      ],
    };
  }
  const fixes: [RegExp, string, string[]][] = [
    [/already open for this branch/, "A pull request already exists", ["Use the open pull request (get_pull_request), or ask the agent to push to it instead of opening another."]],
    [/no commits that aren't on the base/, "Nothing to propose", ["Commit the change to the branch first, then open the pull request."]],
    [/branch moved/, "The branch changed meanwhile", ["Someone pushed to the branch while committing. Run the task again so the agent reads the latest version first; nothing was overwritten."]],
    [/head is now/, "The pull request changed since it was checked", ["Review the new commits, then merge naming the new head commit."]],
    [/person must approve/, "Agents can't approve this", ["Every agent acts as the GitHub App, and GitHub doesn't let an App approve a pull request it opened. A person approves it on GitHub."]],
    [/already exists/, "It already exists", ["Choose another branch name, or use the existing branch."]],
    [/pull request not found/, "No such pull request", ["Issues and pull requests share one numbering, so a number may belong to an issue. Ask the agent to list the open pull requests (list_pull_requests), or give it the number from GitHub."]],
    [/not found/, "Not found", ["Check the path, branch or number. Reads use the default branch unless a ref is given."]],
    [/closed/, "The pull request is closed", ["Reopen it on GitHub, or open a new one."]],
    [/head invalid|base invalid/, "GitHub couldn't use a branch", ["Check that both branches exist. On a private repository the App also needs Contents: read."]],
  ];
  for (const [re, title, f] of fixes) if (re.test(reason)) return { title, meaning: "The policy allowed this, but GitHub refused it (see the reason above). Nothing was changed.", fixes: f };
  return {
    title: s.status === "REFUSED" ? "GitHub refused it" : "The outcome is unknown",
    meaning: s.status === "REFUSED" ? "The policy allowed this, but GitHub refused it (see the reason above). Nothing was changed." : "The policy allowed this, but it didn't complete, and it may or may not have taken effect.",
    fixes: ["Check the repository on GitHub and the audit entry before retrying: a request that timed out may still have succeeded.", "Requests are never retried automatically."],
  };
}

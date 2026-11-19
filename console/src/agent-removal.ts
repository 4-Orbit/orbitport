/**
 * What deleting an agent does to the rules that name it. Rules left behind
 * match nobody, until an agent with the same id is registered again: then
 * they apply to it at once. So deleting an agent offers to delete its rules.
 */
import { fromPolicyJson, removeSpan } from "./rules.ts";
import type { PolicyInfo } from "./types.ts";

export interface AgentRules {
  /** Builder rules for exactly this agent: safe to delete with it. */
  owned: PolicyInfo[];
  /** Other policies that mention the agent (custom Cedar): left for a person to edit. */
  mentions: PolicyInfo[];
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The policies in `text` (described by `infos`) that name the agent. */
export function rulesNamingAgent(infos: PolicyInfo[], text: string, agentId: string): AgentRules {
  const named = new RegExp(`Agent\\s*::\\s*"${escape(agentId)}"`);
  const owned: PolicyInfo[] = [];
  const mentions: PolicyInfo[] = [];
  for (const info of infos) {
    const rule = fromPolicyJson(info.json);
    if (rule?.who.kind === "agent" && rule.who.id === agentId) owned.push(info);
    else if (named.test(text.slice(info.start, info.end))) mentions.push(info);
  }
  return { owned, mentions };
}

/** The text without these policies (spans index `text`). */
export function removePolicies(text: string, infos: PolicyInfo[]): string {
  return [...infos].sort((a, b) => b.start - a.start).reduce((t, info) => removeSpan(t, info.start, info.end), text);
}

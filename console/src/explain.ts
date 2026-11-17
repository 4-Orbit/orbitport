/**
 * Plain-language text for policy.Explain results.
 *
 * The engine (authz.Explain) decides every fact: which forbid matched, which
 * permit is closest and what it is missing, when a time window ends. This
 * module only turns that structure into sentences, so the console never
 * reasons about Cedar itself.
 */
import { capability } from "./rules.ts";
import type { Candidate, EntityRef, Explanation, Requirement } from "./types.ts";

/** One run of text; `policy` renders as a rule-id chip, `strong` in bold. */
export interface Part {
  text: string;
  strong?: boolean;
  policy?: boolean;
}

export interface ExplainText {
  /** The answer to "why was this denied?" in one sentence. */
  headline: Part[];
  /** Further lines: platform notes, other close rules. */
  details: Part[][];
}

/** What was asked, for wording the sentences. */
export interface ExplainedRequest {
  /** Empty or undefined = the account principal. */
  agentId?: string;
  action: string;
  /** The resource id, e.g. a key alias. */
  resource: string;
}

const strong = (text: string): Part => ({ text, strong: true });
const policy = (id: string): Part => ({ text: id, policy: true });
const text = (t: string): Part => ({ text: t });

const fmtDate = (s: number) =>
  new Date(s * 1000).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" });

/** "developer-agent", or "the account" for an account token. */
const who = (r: ExplainedRequest) => (r.agentId ? r.agentId : "the account");

/** "rotate dev-key", "encrypt with dev-key". */
function doing(r: ExplainedRequest): Part[] {
  const cap = capability(r.action);
  if (!cap) return [strong(r.action), text(" on "), strong(r.resource)];
  return [strong(cap.verb), text(cap.prep ? ` ${cap.prep} ` : " "), strong(r.resource)];
}

const entityLabel = (e: EntityRef) => {
  if (e.type === "Role") return `the ${e.id} role`;
  if (e.type === "Action") return capability(e.id)?.verb ?? e.id;
  return e.id;
};

function joinList(items: string[], last = " or "): Part[] {
  const out: Part[] = [];
  items.forEach((item, i) => {
    if (i > 0) out.push(text(i === items.length - 1 ? last : ", "));
    out.push(strong(item));
  });
  return out;
}

/** The roles a principal requirement asks for, if it names any. */
const requiredRoles = (m: Requirement) => (m.entities ?? []).filter((e) => e.type === "Role").map((e) => e.id);

/** What the agent has, for "needs the security role (it has developer)". */
const hasRoles = (agentRoles: string[] | undefined) => (agentRoles && agentRoles.length > 0 ? ` (it has ${agentRoles.join(", ")})` : " (it has no roles)");

/** One missing part as a clause: "needs the security role", "covers only encrypt". */
function clause(m: Requirement, agentRoles: string[] | undefined): Part[] {
  if (m.part === "condition") return [text("its condition isn't met")];
  const names = (m.entities ?? []).map(entityLabel);
  if (m.part === "principal") {
    const roles = requiredRoles(m);
    if (roles.length > 0) return [text("needs "), ...joinList(roles.map((r) => `the ${r} role`)), text(hasRoles(agentRoles))];
    if (m.op === "is") return [text("applies only to "), strong(m.entityType === "Agent" ? "agents" : (m.entityType ?? "other principals"))];
    return [text("applies only to "), ...joinList(names)];
  }
  if (m.op === "is" && !names.length) return [text("covers only "), strong(m.entityType ?? "other resources")];
  return [text("covers only "), ...joinList(names)];
}

/** Every missing scope part of a candidate, as clauses joined by "; ". */
function clauses(c: Candidate, agentRoles: string[] | undefined, withCondition = true): Part[] {
  const out: Part[] = [];
  c.missing
    .filter((m) => withCondition || m.part !== "condition")
    .forEach((m, i) => {
      if (i > 0) out.push(text("; "));
      out.push(...clause(m, agentRoles));
    });
  return out;
}

/** Sentences for one explanation. */
export function explainText(e: Explanation, r: ExplainedRequest): ExplainText {
  const best = e.candidates?.[0];
  const details: Part[][] = [];
  const subject = who(r);

  switch (e.kind) {
    case "allowed":
      return {
        headline: [text("Allowed"), ...(e.determiningPolicies.length ? [text(" by "), ...e.determiningPolicies.map(policy)] : []), text(".")],
        details,
      };
    case "invalidRequest":
      return { headline: [text(`This request is malformed (${e.message ?? "invalid"}), so it's denied without evaluating any rule.`)], details };
    case "noPolicy":
      return { headline: [text("No version is active, so only the platform rules apply and every agent is denied.")], details };
    case "errored":
      return {
        headline: [
          text(`${(e.erroredPolicies?.length ?? 0) === 1 ? "A rule" : "Rules"} failed to evaluate (`),
          ...(e.erroredPolicies ?? []).map(policy),
          text("), and Cedar denies on any error. The details are in the KMS plugin log."),
        ],
        details,
      };
    case "unknownAgent":
      return {
        headline: [strong(subject), text(" isn't declared in this version, so it has no roles and no rule grants it anything.")],
        details: [[text("Add it under Agents & roles on the Policies page.")]],
      };
    case "blocked": {
      const blockers = e.blockedBy ?? [];
      const headline: Part[] = [text("Blocked by ")];
      blockers.forEach((b, i) => {
        if (i > 0) headline.push(text(", "));
        headline.push(policy(b.policyId));
      });
      headline.push(text(". A rule that forbids always wins over any rule that allows."));
      if (blockers.some((b) => b.platform)) {
        details.push([text("Platform rules are built into Orbitport and can't be changed by a tenant.")]);
      }
      if (best) details.push([text("Without it, "), policy(best.policyId), text(" would allow this.")]);
      return { headline, details };
    }
    case "expired":
      return {
        headline: [policy(best!.policyId), text(" would allow this, but it stopped applying on "), strong(fmtDate(best!.window!.at)), text(".")],
        details,
      };
    case "notYet":
      return {
        headline: [policy(best!.policyId), text(" would allow this, but it only applies from "), strong(fmtDate(best!.window!.at)), text(".")],
        details,
      };
    case "conditionFalse":
      return {
        headline: [
          policy(best!.policyId),
          text(" covers "),
          strong(subject),
          text(", this action and this key, but its condition isn't met for this request (for example, a key tag it requires)."),
        ],
        details,
      };
    case "closest": {
      const headline: Part[] = [text("No rule allows this. The closest is "), policy(best!.policyId), text(", but it "), ...clauses(best!, e.agentRoles), text(".")];
      addOthers(details, e, 1);
      return { headline, details };
    }
    case "noRule":
    default: {
      const headline: Part[] = [text("No rule lets "), strong(subject), text(" "), ...doing(r), text(".")];
      addOthers(details, e, 0);
      return { headline, details };
    }
  }
}

/** One line per further candidate: "Related: x covers only encrypt." */
function addOthers(details: Part[][], e: Explanation, from: number) {
  for (const c of (e.candidates ?? []).slice(from)) {
    details.push([text("Related: "), policy(c.policyId), text(" "), ...clauses(c, e.agentRoles), text(".")]);
  }
}

export const partsText = (parts: Part[]) => parts.map((p) => p.text).join("");

/**
 * The plain-language rule model behind the policy builder.
 *
 * A Rule is a small, closed shape: who may (or may never) do what, on which
 * keys or repositories, until when. Cedar stays the source of truth:
 *
 *   - fromPolicyJson() converts the engine's Cedar JSON for one policy into a
 *     Rule, or returns null when the policy uses anything the shape can't
 *     express exactly (it is then shown as a "custom" rule, editable in Cedar);
 *   - toCedar() writes a Rule back as Cedar text.
 *
 * fromPolicyJson(parse(toCedar(r))) === r for every Rule the builder can make;
 * the console's tests check that round trip.
 */

export type Effect = "permit" | "forbid";

export type Who =
  | { kind: "anyone" } // every principal, including account tokens
  | { kind: "anyAgent" } // principal is Agent
  | { kind: "role"; id: string }
  | { kind: "agent"; id: string };

export type On =
  | { kind: "anyKey" }
  | { kind: "keys"; ids: string[] }
  | { kind: "repositories"; ids: string[] }
  | { kind: "tag"; key: string; value: string };

export interface Rule {
  id: string;
  effect: Effect;
  who: Who;
  /** Action ids or group ids (see CAPABILITIES). Empty = every action. */
  can: string[];
  on: On;
  /** Unix seconds; the rule applies only while currentTime < until. */
  until?: number;
}

export interface Capability {
  id: string;
  label: string;
  /** Verb used in sentences, e.g. "encrypt". */
  verb: string;
  /** Preposition before the keys when this is the only capability, e.g. "with". */
  prep: string;
  group?: string;
  resourceType?: "Repository";
}

/** What the builder offers, in display order. Groups first, then single actions. */
export const CAPABILITIES: Capability[] = [
  { id: "github.issue.Create", label: "Create issues", verb: "create issues", prep: "in", resourceType: "Repository" },
  { id: "github.contents.Read", label: "Read files", verb: "read files", prep: "in", resourceType: "Repository" },
  { id: "github.issue.Comment", label: "Comment on issues", verb: "comment on issues", prep: "in", resourceType: "Repository" },
  { id: "github.branch.Create", label: "Create branches", verb: "create branches", prep: "in", resourceType: "Repository" },
  { id: "github.commit.Create", label: "Commit to branches", verb: "commit to branches", prep: "in", resourceType: "Repository" },
  { id: "github.pr.Create", label: "Open pull requests", verb: "open pull requests", prep: "in", resourceType: "Repository" },
  { id: "github.pr.Review", label: "Review pull requests", verb: "review pull requests", prep: "in", resourceType: "Repository" },
  { id: "use", label: "Use keys (encrypt, decrypt, sign, data keys)", verb: "use", prep: "" },
  { id: "kms.Encrypt", label: "Encrypt", verb: "encrypt", prep: "with", group: "use" },
  { id: "kms.Decrypt", label: "Decrypt", verb: "decrypt", prep: "with", group: "use" },
  { id: "kms.Sign", label: "Sign", verb: "sign", prep: "with", group: "use" },
  { id: "kms.GenerateDataKey", label: "Generate data keys", verb: "generate data keys", prep: "from", group: "use" },
  { id: "kms.Encapsulate", label: "Encapsulate (key agreement)", verb: "encapsulate", prep: "with", group: "use" },
  { id: "kms.Decapsulate", label: "Decapsulate (key agreement)", verb: "decapsulate", prep: "with", group: "use" },
  { id: "rotate", label: "Rotate keys", verb: "rotate", prep: "" },
  { id: "kms.RotateKey", label: "Rotate (single action)", verb: "rotate", prep: "", group: "rotate" },
  { id: "read", label: "View key info (metadata, public key)", verb: "view info", prep: "for" },
  { id: "kms.GetKeyMetadata", label: "View key metadata", verb: "view metadata", prep: "for", group: "read" },
  { id: "kms.GetPublicKey", label: "View public key", verb: "view the public key", prep: "of", group: "read" },
  { id: "admin", label: "Create keys", verb: "create", prep: "" },
  { id: "kms.CreateKey", label: "Create keys (single action)", verb: "create", prep: "", group: "admin" },
];

const CAP_BY_ID = new Map(CAPABILITIES.map((c) => [c.id, c]));
const GROUPS = new Set(["use", "rotate", "read", "admin"]);

export const REPOSITORY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/;

export const capability = (id: string): Capability | undefined => CAP_BY_ID.get(id);

// ---------------------------------------------------------------------------
// Cedar JSON (the engine's JSON policy format) -> Rule
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;
interface EntityRef {
  type: string;
  id: string;
}

const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const keysOf = (o: Json) => Object.keys(o);
const isEntity = (v: unknown): v is EntityRef => isObj(v) && typeof v.type === "string" && typeof v.id === "string";

function parseWho(p: unknown): Who | null {
  if (!isObj(p)) return null;
  if (p.op === "All") return { kind: "anyone" };
  if (p.op === "in" && isEntity(p.entity) && p.entity.type === "Role") return { kind: "role", id: p.entity.id };
  if (p.op === "==" && isEntity(p.entity) && p.entity.type === "Agent") return { kind: "agent", id: p.entity.id };
  if (p.op === "is" && p.entity_type === "Agent" && p.in === undefined) return { kind: "anyAgent" };
  return null;
}

function parseCan(a: unknown): string[] | null {
  if (!isObj(a)) return null;
  if (a.op === "All") return [];
  const known = (e: EntityRef) => e.type === "Action" && CAP_BY_ID.has(e.id);
  if ((a.op === "==" || a.op === "in") && isEntity(a.entity)) return known(a.entity) ? [a.entity.id] : null;
  if (a.op === "in" && Array.isArray(a.entities) && a.entities.length > 0 && a.entities.every(isEntity)) {
    const list = a.entities as EntityRef[];
    return list.every(known) ? list.map((e) => e.id) : null;
  }
  return null;
}

/** Flattens a chain of && into its terms. */
function conjuncts(body: unknown): unknown[] {
  if (isObj(body) && keysOf(body).length === 1 && isObj(body["&&"])) {
    const and = body["&&"] as Json;
    return [...conjuncts(and.left), ...conjuncts(and.right)];
  }
  return [body];
}

const isVar = (v: unknown, name: string) => isObj(v) && v.Var === name;
const valueOf = (v: unknown): unknown => (isObj(v) && "Value" in v ? v.Value : undefined);

interface Conditions {
  until?: number;
  tagHas?: string;
  tagEq?: { key: string; value: string };
  keys?: string[];
  repositories?: string[];
}

function parseTerm(term: unknown, into: Conditions): boolean {
  if (!isObj(term) || keysOf(term).length !== 1) return false;
  const [op] = keysOf(term);
  const t = term[op] as Json;
  if (!isObj(t)) return false;
  switch (op) {
    case "<": {
      const left = t.left as Json;
      const n = valueOf(t.right);
      if (isObj(left) && isObj(left["."]) && isVar((left["."] as Json).left, "context") && (left["."] as Json).attr === "currentTime" && typeof n === "number" && into.until === undefined) {
        into.until = n;
        return true;
      }
      return false;
    }
    case "hasTag": {
      const k = valueOf(t.right);
      if (isVar(t.left, "resource") && typeof k === "string" && into.tagHas === undefined) {
        into.tagHas = k;
        return true;
      }
      return false;
    }
    case "==": {
      const left = t.left as Json;
      const v = valueOf(t.right);
      if (isObj(left) && isObj(left.getTag) && isVar((left.getTag as Json).left, "resource")) {
        const k = valueOf((left.getTag as Json).right);
        if (typeof k === "string" && typeof v === "string" && into.tagEq === undefined) {
          into.tagEq = { key: k, value: v };
          return true;
        }
      }
      return false;
    }
    case "in": {
      if (!isVar(t.left, "resource") || !isObj(t.right) || !Array.isArray(t.right.Set) || into.keys || into.repositories) return false;
      const ids: string[] = [];
      let resourceType: string | undefined;
      for (const item of t.right.Set as unknown[]) {
        const ent = isObj(valueOf(item)) ? (valueOf(item) as Json).__entity : undefined;
        if (!isEntity(ent) || !["Key", "Repository"].includes(ent.type)) return false;
        if (resourceType && resourceType !== ent.type) return false;
        resourceType = ent.type;
        ids.push(ent.id);
      }
      if (ids.length < 2) return false;
      if (resourceType === "Repository") into.repositories = ids;
      else into.keys = ids;
      return true;
    }
  }
  return false;
}

/** The Rule a Cedar JSON policy expresses, or null if it doesn't fit the model. */
export function fromPolicyJson(policy: unknown): Rule | null {
  if (!isObj(policy)) return null;
  const annotations = isObj(policy.annotations) ? policy.annotations : {};
  // Unknown annotations would be lost on rewrite, so treat them as custom.
  if (keysOf(annotations).some((k) => k !== "id") || typeof annotations.id !== "string") return null;
  const effect = policy.effect;
  if (effect !== "permit" && effect !== "forbid") return null;

  const who = parseWho(policy.principal);
  const can = parseCan(policy.action);
  if (!who || !can) return null;

  const r = policy.resource;
  let scopeKey: string | null = null;
  let scopeRepository: string | null = null;
  if (!isObj(r)) return null;
  if (r.op === "==" && isEntity(r.entity) && r.entity.type === "Key") scopeKey = r.entity.id;
  else if (r.op === "==" && isEntity(r.entity) && r.entity.type === "Repository") scopeRepository = r.entity.id;
  else if (r.op !== "All") return null;

  const cond: Conditions = {};
  const conditions = Array.isArray(policy.conditions) ? policy.conditions : [];
  for (const c of conditions) {
    if (!isObj(c) || c.kind !== "when") return null;
    for (const term of conjuncts(c.body)) if (!parseTerm(term, cond)) return null;
  }

  // A tag test must be the exact hasTag + getTag pair on one key.
  if ((cond.tagHas === undefined) !== (cond.tagEq === undefined)) return null;
  if (cond.tagHas !== undefined && cond.tagHas !== cond.tagEq!.key) return null;

  const restrictions = [scopeKey !== null, scopeRepository !== null, cond.keys !== undefined, cond.repositories !== undefined, cond.tagEq !== undefined].filter(Boolean).length;
  if (restrictions > 1) return null;

  let on: On = { kind: "anyKey" };
  if (scopeRepository !== null) on = { kind: "repositories", ids: [scopeRepository] };
  else if (cond.repositories) on = { kind: "repositories", ids: cond.repositories };
  else if (scopeKey !== null) on = { kind: "keys", ids: [scopeKey] };
  else if (cond.keys) on = { kind: "keys", ids: cond.keys };
  else if (cond.tagEq) on = { kind: "tag", key: cond.tagEq.key, value: cond.tagEq.value };

  // Mixed service actions and unrestricted GitHub resources stay custom rather
  // than losing their scope when edited in the form.
  const github = can.some((id) => capability(id)?.resourceType === "Repository");
  if (on.kind === "repositories") {
    if (!can.length || can.some((id) => capability(id)?.resourceType !== "Repository")) return null;
    if (on.ids.some((id) => !REPOSITORY_ID_RE.test(id))) return null;
  } else if (github) return null;

  return { id: annotations.id, effect, who, can, on, ...(cond.until !== undefined && { until: cond.until }) };
}

// ---------------------------------------------------------------------------
// Rule -> Cedar
// ---------------------------------------------------------------------------

const str = (s: string) => JSON.stringify(s);
const ent = (type: string, id: string) => `${type}::${str(id)}`;

export function toCedar(rule: Rule): string {
  if (rule.on.kind !== "repositories" && rule.can.some((id) => capability(id)?.resourceType === "Repository")) {
    throw new Error("Choose a repository for the GitHub action");
  }
  const principal =
    rule.who.kind === "anyone"
      ? "principal"
      : rule.who.kind === "anyAgent"
        ? "principal is Agent"
        : rule.who.kind === "role"
          ? `principal in ${ent("Role", rule.who.id)}`
          : `principal == ${ent("Agent", rule.who.id)}`;

  let action = "action";
  if (rule.can.length === 1) {
    const id = rule.can[0];
    action = GROUPS.has(id) ? `action in ${ent("Action", id)}` : `action == ${ent("Action", id)}`;
  } else if (rule.can.length > 1) {
    action = `action in [${rule.can.map((id) => ent("Action", id)).join(", ")}]`;
  }

  let resource = "resource";
  const conds: string[] = [];
  if (rule.on.kind === "repositories") {
    if (!rule.on.ids.length || rule.on.ids.some((id) => !REPOSITORY_ID_RE.test(id)) || !rule.can.length || rule.can.some((id) => capability(id)?.resourceType !== "Repository")) {
      throw new Error("Choose a GitHub action and at least one valid repository");
    }
    if (rule.on.ids.length === 1) resource = `resource == ${ent("Repository", rule.on.ids[0])}`;
    else conds.push(`resource in [${rule.on.ids.map((id) => ent("Repository", id)).join(", ")}]`);
  } else if (rule.on.kind === "keys" && rule.on.ids.length === 1) resource = `resource == ${ent("Key", rule.on.ids[0])}`;
  else if (rule.on.kind === "keys" && rule.on.ids.length > 1) conds.push(`resource in [${rule.on.ids.map((id) => ent("Key", id)).join(", ")}]`);
  else if (rule.on.kind === "tag") conds.push(`resource.hasTag(${str(rule.on.key)}) && resource.getTag(${str(rule.on.key)}) == ${str(rule.on.value)}`);
  if (rule.until !== undefined) conds.push(`context.currentTime < ${Math.floor(rule.until)}`);

  return `@id(${str(rule.id)})\n${rule.effect} (\n  ${principal},\n  ${action},\n  ${resource}\n)${conds.length ? `\nwhen { ${conds.join(" && ")} }` : ""};`;
}

// ---------------------------------------------------------------------------
// Plain language
// ---------------------------------------------------------------------------

export interface Sentence {
  /** Short pieces; `strong` pieces are the user's own values. */
  parts: { text: string; strong?: boolean }[];
}

const fmtTime = (s: number) =>
  new Date(s * 1000).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" });

function listParts(items: string[]): Sentence["parts"] {
  const out: Sentence["parts"] = [];
  items.forEach((item, i) => {
    if (i > 0) out.push({ text: i === items.length - 1 ? " and " : ", " });
    out.push({ text: item, strong: true });
  });
  return out;
}

function whoParts(who: Who): Sentence["parts"] {
  switch (who.kind) {
    case "anyone":
      return [{ text: "Anyone " }, { text: "(agents and account tokens)" }];
    case "anyAgent":
      return [{ text: "Any agent" }];
    case "role":
      return [{ text: "Agents with the " }, { text: who.id, strong: true }, { text: " role" }];
    case "agent":
      return [{ text: who.id, strong: true }];
  }
}

function onParts(on: On): Sentence["parts"] {
  if (on.kind === "anyKey") return [{ text: "any key" }];
  if (on.kind === "tag") return [{ text: "keys tagged " }, { text: `${on.key || "…"} = ${on.value || "…"}`, strong: true }];
  return on.ids.length ? listParts(on.ids) : [{ text: on.kind === "repositories" ? "(choose repositories)" : "(choose keys)" }];
}

/** "Agents with the developer role can encrypt with dev-key until Jan 15, 2027." */
export function describe(rule: Rule): Sentence {
  const parts: Sentence["parts"] = [...whoParts(rule.who)];
  parts.push({ text: rule.effect === "permit" ? " can " : " can never " });
  if (rule.can.length === 0) {
    parts.push({ text: "do anything with " });
  } else {
    const caps = rule.can.map((id) => capability(id) ?? { verb: id, prep: "on" });
    caps.forEach((c, i) => {
      if (i > 0) parts.push({ text: i === caps.length - 1 ? " or " : ", " });
      parts.push({ text: c.verb, strong: true });
    });
    // One capability keeps its own preposition ("encrypt with", "rotate");
    // a list reads "sign, view info or rotate on a and b".
    const prep = caps.length === 1 ? caps[0].prep : "on";
    parts.push({ text: prep ? ` ${prep} ` : " " });
  }
  parts.push(...onParts(rule.on));
  if (rule.until !== undefined) {
    parts.push({ text: rule.effect === "permit" ? ", until " : ", until " });
    parts.push({ text: fmtTime(rule.until), strong: true });
  }
  parts.push({ text: "." });
  return { parts };
}

export const sentenceText = (s: Sentence) => s.parts.map((p) => p.text).join("");

export function isExpired(rule: Rule, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  return rule.until !== undefined && nowSeconds >= rule.until;
}

// ---------------------------------------------------------------------------
// Ids and text edits
// ---------------------------------------------------------------------------

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const validRuleId = (id: string) => ID_RE.test(id) && !id.startsWith("platform.");

/** A readable, unique @id suggestion such as "developer-encrypt-dev-key". */
export function suggestId(rule: Omit<Rule, "id">, taken: Set<string>): string {
  const who = rule.who.kind === "role" || rule.who.kind === "agent" ? rule.who.id : rule.who.kind === "anyAgent" ? "agents" : "anyone";
  const what = rule.can.length === 0 ? "all" : rule.can.length === 1 ? rule.can[0].replace(/^kms\./, "").toLowerCase() : "multi";
  const on = rule.on.kind === "anyKey" ? "any-key" : rule.on.kind === "tag" ? `${rule.on.key}-${rule.on.value}` : rule.on.ids.length === 1 ? rule.on.ids[0] : rule.on.kind === "repositories" ? "repositories" : "keys";
  const base =
    [rule.effect === "forbid" ? "deny" : "", who, what, on]
      .filter(Boolean)
      .join("-")
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 100) || "rule";
  let id = base;
  for (let n = 2; taken.has(id); n++) id = `${base}-${n}`;
  return id;
}

/**
 * When an edited rule kept a name the builder had suggested for it, but the
 * rule now says something else: the name that would be suggested now.
 * Null when the name was chosen by hand or still fits.
 */
export function outdatedSuggestedName(initial: Rule, current: Omit<Rule, "id">, taken: Set<string>): string | null {
  const { id, ...before } = initial;
  if (suggestId(before, taken) !== id) return null;
  const now = suggestId(current, taken);
  return now === id ? null : now;
}

/** Replaces [start, end) of the source with `replacement`. */
export function replaceSpan(source: string, start: number, end: number, replacement: string): string {
  return source.slice(0, start) + replacement + source.slice(end);
}

/** Removes a policy and the blank line it leaves behind. */
export function removeSpan(source: string, start: number, end: number): string {
  let s = start;
  let e = end;
  while (e < source.length && (source[e] === " " || source[e] === "\t")) e++;
  if (source[e] === "\n") e++;
  if (source[e] === "\n" && (s === 0 || source[s - 1] === "\n")) e++;
  return source.slice(0, s) + source.slice(e);
}

/** Appends a policy, separated by one blank line. */
export function appendPolicy(source: string, text: string): string {
  const trimmed = source.replace(/\s*$/, "");
  return (trimmed ? `${trimmed}\n\n` : "") + text + "\n";
}

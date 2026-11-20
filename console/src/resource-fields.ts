/**
 * Which resource an action takes, and what the resource field should hold
 * when the action changes. Pure, so the console's unit tests cover it.
 */
import { capability, REPOSITORY_ID_RE } from "./rules.ts";
import type { ActionInfo } from "./types.ts";

export type ResourceType = "Key" | "Repository";

/**
 * The resource type an action applies to. The gateway's schema is the source
 * of truth; until it loads, the rule model's capabilities say which actions
 * take a Repository (every other action takes a Key).
 */
export function resourceTypeOf(action: string, schemaActions?: ActionInfo[] | null): ResourceType {
  const fromSchema = schemaActions?.find((a) => a.name === action)?.resourceType;
  if (fromSchema === "Repository" || fromSchema === "Key") return fromSchema;
  return capability(action)?.resourceType ?? "Key";
}

/** The key the simulator starts on when it exists. */
export const PREFERRED_KEY = "dev-key";

export interface ResourceOptions {
  keys: string[];
  repositories: string[];
}

/** A sensible starting resource of the given type, or "" when none is known. */
export function defaultResource(type: ResourceType, options: ResourceOptions): string {
  if (type === "Repository") return options.repositories[0] ?? "";
  return options.keys.includes(PREFERRED_KEY) ? PREFERRED_KEY : (options.keys[0] ?? "");
}

/**
 * The resource id to show after the action changes: kept when the resource
 * type stays the same, otherwise reset to a default of the new type, so a key
 * alias is never sent as a repository (or the reverse).
 */
export function resourceForAction(prevType: ResourceType, nextType: ResourceType, prevId: string, options: ResourceOptions): string {
  return prevType === nextType ? prevId : defaultResource(nextType, options);
}

/** Label and placeholder for the resource field. */
export function resourceField(type: ResourceType): { label: string; placeholder: string; noun: string } {
  return type === "Repository" ? { label: "Resource (repository)", placeholder: "owner/repo", noun: "repository" } : { label: "Resource (key)", placeholder: "key alias", noun: "key" };
}

/** Why a resource id can't be used for this type, or null when it can. */
export function resourceProblem(type: ResourceType, id: string): string | null {
  if (!id) return `Choose a ${resourceField(type).noun}.`;
  if (type === "Repository" && !REPOSITORY_ID_RE.test(id)) return "Enter the repository as owner/repo.";
  return null;
}

/** Actions grouped for an <optgroup> select, in schema order. */
export function actionGroups(actions: ActionInfo[]): [string, string[]][] {
  const g = new Map<string, string[]>();
  for (const a of actions) g.set(a.group, [...(g.get(a.group) ?? []), a.name]);
  return [...g.entries()];
}

/**
 * Agents for the Activity filter: the ones the active version registers, and
 * the ones seen elsewhere (older versions, loaded audit events) that it no
 * longer registers. Both sorted; no id appears twice.
 */
export function splitAgents(registered: string[], seen: Iterable<string>): { registered: string[]; removed: string[] } {
  const now = new Set(registered);
  const removed = new Set<string>();
  for (const id of seen) if (id && !now.has(id)) removed.add(id);
  return { registered: [...now].sort(), removed: [...removed].sort() };
}


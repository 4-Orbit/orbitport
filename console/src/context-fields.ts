/**
 * Trusted context for actions that declare it (D-035): the fields the
 * gateway's schema lists for an action, their what-if defaults for Simulate
 * and Tests, and a check that every required field has a value. Enforcement
 * computes these from GitHub; here they are typed in.
 */
import type { ContextField } from "./types.ts";

export type ContextValue = string | boolean | number | string[];
export type ContextValues = Record<string, ContextValue>;

/** A neutral starting value for each field. Optional fields start unset. */
export function defaultContext(fields: ContextField[] | undefined): ContextValues {
  const out: ContextValues = {};
  for (const f of fields ?? []) {
    if (f.optional) continue;
    out[f.name] = f.type === "Bool" ? false : f.type === "Long" ? 0 : f.type === "Set<String>" ? [] : "";
  }
  return out;
}

/** The context to send: declared fields only, empty optional ones left out. Undefined when the action has none. */
export function contextForRequest(fields: ContextField[] | undefined, values: ContextValues): ContextValues | undefined {
  if (!fields?.length) return undefined;
  const out: ContextValues = {};
  for (const f of fields) {
    const v = values[f.name];
    if (v === undefined || (f.optional && v === "")) continue;
    out[f.name] = v;
  }
  return out;
}

/** "a.go, b/c.go" -> ["a.go", "b/c.go"] */
export const parseSet = (text: string): string[] =>
  text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

/** Why the context can't be sent, or null. */
export function contextProblem(fields: ContextField[] | undefined, values: ContextValues): string | null {
  for (const f of fields ?? []) {
    const v = values[f.name];
    if (f.optional) continue;
    if (v === undefined) return `Set ${f.name}.`;
    if (f.type === "Long" && (typeof v !== "number" || !Number.isInteger(v))) return `${f.name} must be a whole number.`;
  }
  return null;
}

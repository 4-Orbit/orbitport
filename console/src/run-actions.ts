/**
 * Actions "Run it for real" may send to the KMS: none of them changes a
 * key. Shared by the console server (which enforces it) and the browser
 * (which only offers the button for these).
 */
import type { SimRequest } from "./types.ts";

export const RUN_ACTIONS = ["kms.Encrypt", "kms.Decrypt", "kms.Sign", "kms.GenerateDataKey", "kms.GetKeyMetadata", "kms.GetPublicKey"] as const;
export type RunAction = (typeof RUN_ACTIONS)[number];

export const isRunAction = (a: string): a is RunAction => (RUN_ACTIONS as readonly string[]).includes(a);

/** Why a request can't be run for real, or null when it can. */
export function cannotRun(r: SimRequest): string | null {
  if (!r.agentId) return "Run it for real works for agents; account tokens are always allowed.";
  if ((r.resource.type ?? "Key") !== "Key" || !isRunAction(r.action)) return "Run it for real only sends actions that don't change a key (encrypt, decrypt, sign, data keys, metadata, public key).";
  return null;
}

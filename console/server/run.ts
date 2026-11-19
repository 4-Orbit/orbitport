import { createHash } from "node:crypto";
import { callGateway, type GatewayResult } from "./gateway.ts";

/**
 * "Run it for real": send one request to the KMS *as an agent* and report
 * what enforcement decided.
 *
 * The console server mints a short-lived token for that agent through
 * policy.IssueAgentToken (with the operator token), calls the KMS with the
 * agent token, and reads the decision from the KMS's own audit event, found
 * by the token's jti hash. The operator token never reaches the KMS on this
 * path (it would be allowed everything and prove nothing), the agent token
 * never leaves this process, and no key material is returned.
 */

import { RUN_ACTIONS, type RunAction } from "../src/run-actions.ts";

export { RUN_ACTIONS, type RunAction };

export interface RunRequest {
  agentId: string;
  action: RunAction;
  /** Key alias, e.g. "dev-key" (a "kms:" prefix is accepted). */
  keyId: string;
  /** For kms.Sign; the KMS rejects an algorithm that doesn't fit the key. */
  signingAlgorithm?: string;
}

export interface RunResult {
  /** The KMS's decision, from its audit event; null if no event was found. */
  decision: "ALLOW" | "DENY" | null;
  /** Whether the KMS performed the operation (only ever after an ALLOW). */
  kmsCalled: boolean | null;
  /** What came back, never the payload: "ciphertext returned", or the error. */
  outcome: string;
  /** True when the call returned an error (after an ALLOW, the KMS refused it). */
  failed: boolean;
  determiningPolicies: string[];
  /** The version the KMS enforced, from the audit event. */
  policyVersion: number | null;
  /** The audit event, for linking to Activity. */
  requestId: string | null;
  /** The minted token's short hash; Activity marks events with it. */
  jtiHash: string;
}

export const AGENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$/;

export function parseRunRequest(v: unknown): RunRequest | string {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return "expected {agentId, action, keyId}";
  const { agentId, action, keyId, signingAlgorithm, ...rest } = v as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return `unknown field ${Object.keys(rest)[0]}`;
  if (typeof agentId !== "string" || !AGENT_ID_RE.test(agentId)) return "agentId must be a registered agent id";
  if (typeof action !== "string" || !(RUN_ACTIONS as readonly string[]).includes(action)) return `action must be one of ${RUN_ACTIONS.join(", ")}`;
  if (typeof keyId !== "string" || !KEY_RE.test(keyId)) return "keyId must be a key alias";
  if (signingAlgorithm !== undefined && (typeof signingAlgorithm !== "string" || !/^[A-Z0-9_]{1,40}$/.test(signingAlgorithm))) return "invalid signingAlgorithm";
  return { agentId, action: action as RunAction, keyId, ...(signingAlgorithm !== undefined && { signingAlgorithm: signingAlgorithm as string }) };
}

/** Same as the gateway's hash_jti and Go's authz.HashJTI. */
export function hashJti(jti: string): string {
  return jti ? createHash("sha256").update(jti).digest("hex").slice(0, 16) : "";
}

/** The jti claim of a JWT, read without verifying (it's our own fresh token). */
export function jtiOf(token: string): string {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")) as { jti?: unknown };
    return typeof payload.jti === "string" ? payload.jti : "";
  } catch {
    return "";
  }
}

const SAMPLE = Buffer.from("orbitport console run").toString("base64");

/** KMS params for each action, with sample data only. */
export function kmsParams(r: RunRequest): Record<string, unknown> {
  const KeyId = r.keyId.startsWith("kms:") ? r.keyId : `kms:${r.keyId}`;
  switch (r.action) {
    case "kms.Encrypt":
      return { KeyId, Plaintext: SAMPLE };
    case "kms.Decrypt":
      // Not a real ciphertext: Cedar decides on KeyId before the KMS reads
      // the blob, so a DENY is real and an ALLOW ends in a KMS error.
      return { KeyId, CiphertextBlob: "orbitport-console-sample" };
    case "kms.Sign":
      return { KeyId, Message: SAMPLE, MessageType: "RAW", SigningAlgorithm: r.signingAlgorithm ?? "ECDSA_SHA_256" };
    case "kms.GenerateDataKey":
    case "kms.GetKeyMetadata":
    case "kms.GetPublicKey":
      return { KeyId };
  }
}

/** A description of a successful result that never includes its contents. */
function describeSuccess(action: RunAction): string {
  switch (action) {
    case "kms.Encrypt":
      return "the KMS encrypted the sample text (ciphertext not shown)";
    case "kms.Decrypt":
      return "the KMS decrypted the sample (plaintext not shown)";
    case "kms.Sign":
      return "the KMS signed the sample message (signature not shown)";
    case "kms.GenerateDataKey":
      return "the KMS generated a data key (not shown)";
    case "kms.GetKeyMetadata":
      return "the KMS returned the key's metadata";
    case "kms.GetPublicKey":
      return "the KMS returned the public key (not shown)";
  }
}

export interface RunDeps {
  gatewayUrl: string;
  fetchImpl: typeof fetch;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}

interface CachedToken {
  token: string;
  jtiHash: string;
  /** Epoch ms after which a new token is minted. */
  renewAt: number;
}

/**
 * Lifetime of a console-run agent token. Kept short, but clear of the
 * issuer's 60-second minimum: issuers without the whole-second fix reject
 * a token at exactly the minimum.
 */
export const RUN_TOKEN_TTL_SECONDS = 120;
/** Runs allowed per minute, across the console. */
export const RUN_RATE_PER_MINUTE = 20;
/** How long to wait for the KMS's audit event to arrive. */
const AUDIT_WAIT_MS = 2500;
const AUDIT_POLL_MS = 200;
/** Console-run token hashes remembered for Activity labels. */
const MAX_REMEMBERED = 500;

export class RunError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * State for console runs: cached agent tokens (in memory only), the rate
 * limit, and the hashes of tokens this console minted.
 */
export class Runner {
  private tokens = new Map<string, CachedToken>();
  private recent: number[] = [];
  private minted: string[] = [];

  constructor(private deps: RunDeps) {}

  /** Short hashes of tokens this console minted, oldest first. */
  consoleRuns(): string[] {
    return [...this.minted];
  }

  async run(operatorToken: string, r: RunRequest): Promise<RunResult> {
    this.takeRateSlot();
    const agent = await this.agentToken(operatorToken, r.agentId);
    const startedAt = this.deps.now();
    const call = await callGateway(this.deps.gatewayUrl, agent.token, { method: r.action, params: kmsParams(r) }, this.deps.fetchImpl);
    const event = await this.findAuditEvent(operatorToken, agent.jtiHash, r.action, startedAt);
    const error = "error" in call.body ? call.body.error : null;
    return {
      decision: event?.decision ?? null,
      kmsCalled: event?.kmsCalled ?? null,
      outcome: error ? error.message : describeSuccess(r.action),
      failed: error !== null,
      determiningPolicies: event?.determiningPolicies ?? [],
      policyVersion: event?.policyVersion ?? null,
      requestId: event?.requestId ?? null,
      jtiHash: agent.jtiHash,
    };
  }

  async createGithubIssue(operatorToken: string, r: GithubIssueRequest): Promise<unknown> {
    this.takeRateSlot();
    const agent = await this.agentToken(operatorToken, r.agentId);
    const out = await callGateway(this.deps.gatewayUrl, agent.token, {
      method: "github.issue.Create", params: { repository: r.repository, title: r.title, body: r.body },
    }, this.deps.fetchImpl);
    if ("error" in out.body) throw new RunError(out.status === 200 ? 502 : out.status, out.body.error.message);
    return out.body.result;
  }

  private takeRateSlot() {
    const now = this.deps.now();
    this.recent = this.recent.filter((t) => now - t < 60_000);
    if (this.recent.length >= RUN_RATE_PER_MINUTE) throw new RunError(429, `at most ${RUN_RATE_PER_MINUTE} runs per minute; try again shortly`);
    this.recent.push(now);
  }

  private async agentToken(operatorToken: string, agentId: string): Promise<CachedToken> {
    const cached = this.tokens.get(agentId);
    if (cached && this.deps.now() < cached.renewAt) return cached;
    const out = await callGateway(
      this.deps.gatewayUrl,
      operatorToken,
      { method: "policy.IssueAgentToken", params: { agentId, ttlSeconds: RUN_TOKEN_TTL_SECONDS } },
      this.deps.fetchImpl,
    );
    if ("error" in out.body) throw new RunError(out.status === 200 ? 400 : out.status, `couldn't get a token for ${agentId}: ${out.body.error.message}`);
    const token = (out.body.result as { token?: unknown } | null)?.token;
    if (typeof token !== "string" || !token) throw new RunError(502, "the gateway returned no agent token");
    const jtiHash = hashJti(jtiOf(token));
    if (!jtiHash) throw new RunError(502, "the agent token has no jti");
    // Renew well before expiry so a run never races the token's end.
    const entry = { token, jtiHash, renewAt: this.deps.now() + (RUN_TOKEN_TTL_SECONDS - 15) * 1000 };
    this.tokens.set(agentId, entry);
    this.minted.push(jtiHash);
    if (this.minted.length > MAX_REMEMBERED) this.minted.splice(0, this.minted.length - MAX_REMEMBERED);
    return entry;
  }

  /** The KMS audits asynchronously, so poll briefly for this run's event. */
  private async findAuditEvent(operatorToken: string, jtiHash: string, action: string, startedAt: number): Promise<AuditEvent | null> {
    const want = `Action::"${action}"`;
    const deadline = this.deps.now() + AUDIT_WAIT_MS;
    for (;;) {
      const out: GatewayResult = await callGateway(this.deps.gatewayUrl, operatorToken, { method: "policy.ListAudit", params: { jtiHash, limit: 10 } }, this.deps.fetchImpl);
      if ("result" in out.body) {
        const events = ((out.body.result as { events?: AuditEvent[] } | null)?.events ?? []).filter(
          (e) => e.action === want && Date.parse(e.ts) >= startedAt - 1000,
        );
        if (events[0]) return events[0];
      }
      if (this.deps.now() >= deadline) return null;
      await this.deps.sleep(AUDIT_POLL_MS);
    }
  }
}

interface AuditEvent {
  ts: string;
  requestId: string;
  action: string;
  decision: "ALLOW" | "DENY";
  determiningPolicies: string[];
  policyVersion: number;
  kmsCalled: boolean;
}

export interface GithubIssueRequest {
  agentId: string;
  repository: string;
  title: string;
  body: string;
}

export function parseGithubIssueRequest(v: unknown): GithubIssueRequest | string {
  if (!v || typeof v !== "object" || Array.isArray(v)) return "expected an issue request";
  const { agentId, repository, title, body, ...rest } = v as Record<string, unknown>;
  if (Object.keys(rest).length) return "unknown issue request field";
  if (typeof agentId !== "string" || !AGENT_ID_RE.test(agentId)) return "choose a registered agent";
  if (typeof repository !== "string" || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/.test(repository)) return "choose a repository";
  if (typeof title !== "string" || !title.trim() || Buffer.byteLength(title) > 256) return "title must be 1–256 bytes";
  if (typeof body !== "string" || Buffer.byteLength(body) > 60000) return "body must be at most 60000 bytes";
  return { agentId, repository, title, body };
}

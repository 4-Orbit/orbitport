/**
 * Compare a simulated decision with what the KMS really decided for the
 * same request ("Run it for real").
 *
 * They can differ for legitimate reasons: the simulation used the draft or
 * another version, a simulated time, or the KMS hasn't picked up a version
 * that was just activated (its policy cache lasts about 5 seconds). Only a
 * difference on the same version at the current time is a bug, and the
 * console says so loudly.
 */
import type { Decision, RunResult } from "./types.ts";

export interface Simulated {
  decision: Decision;
  /** Simulate's source label: "draft", "v4", or "none (platform policy only)". */
  source: string;
  simulatedTime: boolean;
}

export type CompareTone = "agree" | "expected" | "disagree" | "unknown";

export interface Comparison {
  tone: CompareTone;
  message: string;
}

const sourceName = (s: string) => (s === "draft" ? "your draft" : s.startsWith("v") ? s : "no version");

export function compareRun(sim: Simulated, real: RunResult): Comparison {
  if (real.decision === null) {
    return {
      tone: "unknown",
      message: "The KMS's audit event didn't arrive in time, so its decision can't be shown here. It will appear on Activity shortly.",
    };
  }
  const enforced = real.policyVersion ? `v${real.policyVersion}` : "no version";
  const sameSource = sim.source === enforced || (!real.policyVersion && !sim.source.startsWith("v") && sim.source !== "draft");
  const same = sim.decision === real.decision;

  if (same) {
    if (!sameSource) return { tone: "agree", message: `Both decided ${real.decision}, although you simulated ${sourceName(sim.source)} and the KMS enforces ${enforced}.` };
    if (sim.simulatedTime) return { tone: "agree", message: `Both decided ${real.decision}. The KMS used the current time, not your simulated time.` };
    return { tone: "agree", message: `The KMS agrees with the simulation: ${real.decision} under ${enforced}.` };
  }
  if (sim.source === "draft") {
    return {
      tone: "expected",
      message: `You simulated your draft, but the KMS enforces ${enforced}. Save and activate the draft to make ${sim.decision} the real decision.`,
    };
  }
  if (!sameSource) {
    return {
      tone: "expected",
      message: `You simulated ${sourceName(sim.source)}, but the KMS enforced ${enforced}. If you just activated ${sourceName(sim.source)}, the KMS picks it up within about 5 seconds; run it again.`,
    };
  }
  if (sim.simulatedTime) {
    return { tone: "expected", message: `You simulated a different time; the KMS used the current time, and a time-limited rule can decide differently.` };
  }
  return {
    tone: "disagree",
    message: `The simulation and the KMS disagree on the same version (${enforced}) at the same time. This shouldn't happen: please report it with the request id.`,
  };
}

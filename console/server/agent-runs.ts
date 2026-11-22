/**
 * Gemini agent runs, held by the console server so a run outlives the page
 * that started it: the browser polls for progress, can switch pages, reload
 * and reattach, and can ask to stop. One run at a time per console.
 */
import { randomBytes } from "node:crypto";
import type { AgentRun, AgentStep } from "./gemini-agent.ts";

export interface RunState {
  id: string;
  agentId: string;
  repository: string;
  mode: "mock" | "real" | null;
  startedAt: number;
  /** running until the loop returns; stopping once Stop was asked for. */
  status: "running" | "stopping" | "done";
  steps: AgentStep[];
  /** The finished run (status done). */
  run?: AgentRun;
  error?: string;
  finishedAt?: number;
}

/** Finished runs are kept this long, for the page to show and reattach. */
export const KEEP_FINISHED_MS = 10 * 60_000;

export class AgentRuns {
  private runs = new Map<string, { state: RunState; abort: AbortController }>();
  private latestId: string | null = null;

  constructor(private now: () => number = Date.now) {}

  /** The run in progress, if any. */
  active(): RunState | null {
    for (const { state } of this.runs.values()) if (state.status !== "done") return state;
    return null;
  }

  /**
   * Starts body in the background. body receives the stop signal and a
   * progress callback, and resolves to the finished run.
   */
  start(
    meta: Pick<RunState, "agentId" | "repository" | "mode">,
    body: (signal: AbortSignal, onStep: (steps: AgentStep[]) => void) => Promise<AgentRun>,
  ): RunState {
    this.prune();
    const abort = new AbortController();
    const state: RunState = { id: randomBytes(9).toString("base64url"), ...meta, startedAt: this.now(), status: "running", steps: [] };
    this.runs.set(state.id, { state, abort });
    this.latestId = state.id;
    void body(abort.signal, (steps) => {
      state.steps = steps;
    })
      .then((run) => {
        state.run = run;
        state.steps = run.steps;
      })
      .catch((e: unknown) => {
        state.error = e instanceof Error ? e.message : "the run failed";
      })
      .finally(() => {
        state.status = "done";
        state.finishedAt = this.now();
      });
    return state;
  }

  get(id: string): RunState | null {
    return this.runs.get(id)?.state ?? null;
  }

  latest(): RunState | null {
    return this.latestId ? this.get(this.latestId) : null;
  }

  /** Asks a run to stop at its next safe point. False if it isn't running. */
  stop(id: string): boolean {
    const entry = this.runs.get(id);
    if (!entry || entry.state.status === "done") return false;
    entry.state.status = "stopping";
    entry.abort.abort();
    return true;
  }

  private prune() {
    for (const [id, { state }] of this.runs) {
      if (state.status === "done" && this.now() - (state.finishedAt ?? 0) > KEEP_FINISHED_MS) this.runs.delete(id);
    }
  }
}

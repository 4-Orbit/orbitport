import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "./api.ts";
import type { AgentRunState } from "./types.ts";

import { POLL_MS, TOAST_LINGER_MS } from "./agent-run-timing.ts";

interface AgentRunApi {
  /** The current or most recent run (null before any). */
  current: AgentRunState | null;
  /** Show the corner toast: while running, and briefly after finishing. */
  toastVisible: boolean;
  error: string | null;
  start: (agentId: string, repository: string, task: string) => Promise<void>;
  stop: () => Promise<void>;
}

const Ctx = createContext<AgentRunApi | null>(null);

/**
 * The Gemini agent run, above the pages: it keeps polling while the
 * operator switches tabs, and reattaches to a run in progress after a reload.
 */
export function AgentRunProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<AgentRunState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lingerUntil, setLingerUntil] = useState(0);
  const [, setTick] = useState(0);
  const seenRunning = useRef<string | null>(null);

  // Reattach to the latest run (for example after a reload).
  useEffect(() => {
    api.latestAgentRun().then((r) => r && setCurrent(r)).catch(() => undefined);
  }, []);

  const running = !!current && current.status !== "done";
  useEffect(() => {
    if (!current || !running) return;
    seenRunning.current = current.id;
    const t = setInterval(() => {
      api
        .agentRun(current.id)
        .then(setCurrent)
        .catch((e: Error) => setError(e.message));
    }, POLL_MS);
    return () => clearInterval(t);
  }, [current?.id, running]);

  // A run seen running that has just finished lingers in the toast.
  useEffect(() => {
    if (current?.status === "done" && seenRunning.current === current.id) {
      seenRunning.current = null;
      const until = Date.now() + TOAST_LINGER_MS;
      setLingerUntil(until);
      const t = setTimeout(() => setTick((n) => n + 1), TOAST_LINGER_MS + 50);
      return () => clearTimeout(t);
    }
  }, [current?.status, current?.id]);

  const start = useCallback(async (agentId: string, repository: string, task: string) => {
    setError(null);
    setCurrent(await api.startGeminiAgent(agentId, repository, task, true));
  }, []);
  const stop = useCallback(async () => {
    if (!current) return;
    try {
      setCurrent(await api.stopAgentRun(current.id));
    } catch (e) {
      setError((e as Error).message);
    }
  }, [current]);

  const toastVisible = running || Date.now() < lingerUntil;
  return <Ctx.Provider value={{ current, toastVisible, error, start, stop }}>{children}</Ctx.Provider>;
}

export function useAgentRun(): AgentRunApi {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAgentRun outside AgentRunProvider");
  return v;
}

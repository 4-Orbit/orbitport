import { useCallback, useEffect, useRef, useState } from "react";

export const POLL_MS = 5000;

export interface Polled<T> {
  data: T | null;
  /** Set when the latest fetch failed; `data` keeps the last good value. */
  error: string | null;
  updatedAt: Date | null;
  refresh: () => Promise<void>;
}

/** Fetches now, then every POLL_MS. */
export function usePolling<T>(load: () => Promise<T>, intervalMs = POLL_MS): Polled<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const loadRef = useRef(load);
  loadRef.current = load;

  const refresh = useCallback(async () => {
    try {
      setData(await loadRef.current());
      setError(null);
      setUpdatedAt(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), intervalMs);
    return () => clearInterval(id);
  }, [refresh, intervalMs]);

  return { data, error, updatedAt, refresh };
}

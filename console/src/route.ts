import { useEffect, useState } from "react";

export const PAGES = ["activity", "access", "policies", "simulate", "tests", "versions", "agents"] as const;
export type Page = (typeof PAGES)[number];

export interface Route {
  page: Page;
  /** Selected audit request on the Activity page. */
  requestId: string | null;
}

/** `#/<page>` or `#/activity/<requestId>`. Anything else is the Activity page. */
export function parseHash(hash: string): Route {
  const [, page = "", id] = hash.replace(/^#/, "").split("/");
  if ((PAGES as readonly string[]).includes(page)) {
    return { page: page as Page, requestId: page === "activity" && id ? safeDecode(id) : null };
  }
  return { page: "activity", requestId: null };
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export const go = (page: Page, id?: string) => {
  window.location.hash = `#/${page}${id ? `/${encodeURIComponent(id)}` : ""}`;
};

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

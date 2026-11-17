/**
 * Cursor paging helpers. Every list endpoint returns `nextCursor` ("" = last
 * page). The console never drops items silently: callers learn whether more
 * exist and say so in the UI.
 */
export interface Page<T> {
  items: T[];
  nextCursor: string;
}

export interface Collected<T> {
  items: T[];
  /** True when the server had more than `maxItems`. */
  more: boolean;
  nextCursor: string;
}

/**
 * Follows cursors until the list ends or `maxItems` are collected. Items with
 * a key already seen are skipped, so a list that shifts between pages never
 * shows duplicates. Stops if a page repeats its cursor (a server bug guard).
 */
export async function collectPages<T>(fetchPage: (cursor: string) => Promise<Page<T>>, key: (item: T) => string, maxItems: number): Promise<Collected<T>> {
  const seen = new Set<string>();
  const items: T[] = [];
  let cursor = "";
  for (;;) {
    const page = await fetchPage(cursor);
    for (const item of page.items) {
      const k = key(item);
      if (seen.has(k)) continue;
      seen.add(k);
      items.push(item);
    }
    if (!page.nextCursor || page.nextCursor === cursor) return { items, more: false, nextCursor: "" };
    if (items.length >= maxItems) return { items: items.slice(0, maxItems), more: true, nextCursor: page.nextCursor };
    cursor = page.nextCursor;
  }
}

/** Appends a page to a list, skipping items already present. */
export function appendPage<T>(existing: T[], page: T[], key: (item: T) => string): T[] {
  const have = new Set(existing.map(key));
  return [...existing, ...page.filter((i) => !have.has(key(i)))];
}

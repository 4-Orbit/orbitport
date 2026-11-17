import { test } from "node:test";
import assert from "node:assert/strict";
import { appendPage, collectPages, type Page } from "../src/paging.ts";

/** A fake server listing ids 1..total, `size` per page, cursor = last id. */
function server(total: number, size: number) {
  const calls: string[] = [];
  const fetchPage = async (cursor: string): Promise<Page<number>> => {
    calls.push(cursor);
    const start = cursor ? Number(cursor) : 0;
    const items = Array.from({ length: Math.min(size, total - start) }, (_, i) => start + i + 1);
    const last = items.at(-1) ?? start;
    return { items, nextCursor: last < total ? String(last) : "" };
  };
  return { fetchPage, calls };
}

test("collects every page until the list ends", async () => {
  const s = server(450, 200);
  const r = await collectPages(s.fetchPage, String, 2000);
  assert.equal(r.items.length, 450);
  assert.equal(r.more, false);
  assert.deepEqual(s.calls, ["", "200", "400"]);
});

test("stops at maxItems and says more exist instead of dropping silently", async () => {
  const s = server(5000, 200);
  const r = await collectPages(s.fetchPage, String, 1000);
  assert.equal(r.items.length, 1000);
  assert.equal(r.more, true);
  assert.equal(r.nextCursor, "1000");
});

test("skips duplicates when the list shifts between pages", async () => {
  const pages: Page<string>[] = [
    { items: ["a", "b"], nextCursor: "b" },
    { items: ["b", "c"], nextCursor: "c" },
    { items: ["d"], nextCursor: "" },
  ];
  let i = 0;
  const r = await collectPages(async () => pages[i++], (x) => x, 100);
  assert.deepEqual(r.items, ["a", "b", "c", "d"]);
});

test("a server repeating its cursor cannot loop forever", async () => {
  const r = await collectPages(async () => ({ items: ["x"], nextCursor: "same" }), (x) => x, 100);
  assert.deepEqual(r.items, ["x"]);
});

test("appendPage keeps order and drops items already shown", () => {
  const v = (n: number) => ({ version: n });
  const merged = appendPage([v(5), v(4), v(3)], [v(3), v(2), v(1)], (x) => String(x.version));
  assert.deepEqual(merged.map((x) => x.version), [5, 4, 3, 2, 1]);
});

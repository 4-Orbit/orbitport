import { test } from "node:test";
import assert from "node:assert/strict";
import { draftReducer, type DraftStore } from "../src/draft-history.ts";

const start = (): DraftStore => ({ draft: { policies: "A", entities: [], base: 1, dirty: false }, past: [], future: [], lastTypingAt: 0 });
const role = (id: string) => ({ uid: { type: "Role", id }, attrs: {}, parents: [] });

test("labeled changes undo and redo in order", () => {
  let s = start();
  s = draftReducer(s, { type: "commit", next: { entities: [role("developer")] }, label: "add role developer" });
  s = draftReducer(s, { type: "commit", next: { entities: [] }, label: "delete role developer" });
  assert.equal(s.past.at(-1)?.label, "delete role developer");

  s = draftReducer(s, { type: "undo" });
  assert.deepEqual(s.draft.entities, [role("developer")], "undo restores the deleted role");
  assert.equal(s.future.at(-1)?.label, "delete role developer");

  s = draftReducer(s, { type: "redo" });
  assert.deepEqual(s.draft.entities, []);
  s = draftReducer(s, { type: "undo" });
  s = draftReducer(s, { type: "undo" });
  assert.deepEqual(s.draft.entities, []);
  assert.equal(s.draft.policies, "A");
  assert.equal(draftReducer(s, { type: "undo" }), s, "nothing left to undo is a no-op");
});

test("typing merges into one step per pause, and a new edit clears redo", () => {
  let s = start();
  s = draftReducer(s, { type: "type", policies: "AB", at: 1000 });
  s = draftReducer(s, { type: "type", policies: "ABC", at: 1500 });
  s = draftReducer(s, { type: "type", policies: "ABCD", at: 2000 });
  assert.equal(s.past.length, 1, "quick typing is one undo step");
  s = draftReducer(s, { type: "type", policies: "ABCDE", at: 9000 });
  assert.equal(s.past.length, 2, "a pause starts a new step");

  s = draftReducer(s, { type: "undo" });
  assert.equal(s.draft.policies, "ABCD");
  s = draftReducer(s, { type: "type", policies: "ABCDX", at: 20000 });
  assert.equal(s.future.length, 0, "editing after undo drops the redo stack");
});

test("load is undoable and resets the dirty flag; markSaved records the version", () => {
  let s = draftReducer(start(), { type: "type", policies: "mine", at: 1 });
  assert.equal(s.draft.dirty, true);
  s = draftReducer(s, { type: "load", bundle: { policies: "active", entities: [] }, base: 7, label: "load active v7" });
  assert.equal(s.draft.dirty, false);
  assert.equal(s.draft.base, 7);
  s = draftReducer(s, { type: "undo" });
  assert.equal(s.draft.policies, "mine", "an accidental Load active can be undone");
  s = draftReducer(s, { type: "markSaved", base: 8 });
  assert.deepEqual([s.draft.base, s.draft.dirty], [8, false]);
});

test("history is bounded", () => {
  let s = start();
  for (let i = 0; i < 150; i++) s = draftReducer(s, { type: "commit", next: { policies: `p${i}` }, label: `c${i}` });
  assert.equal(s.past.length, 100);
});

import { useEffect, useRef } from "react";
import { Annotation, EditorState, type Extension } from "@codemirror/state";

/** Marks a document replacement that came from props, not from typing. */
const External = Annotation.define<boolean>();
import { EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { HighlightStyle, syntaxHighlighting, bracketMatching } from "@codemirror/language";
import { linter, lintGutter, setDiagnostics, type Diagnostic } from "@codemirror/lint";
import { tags as t } from "@lezer/highlight";
import { cedarLanguage } from "../cedar-lang.ts";
import type { Problem } from "../types.ts";

const highlight = HighlightStyle.define([
  { tag: t.keyword, color: "#c7a2ff" },
  { tag: t.strong, color: "#ff9e64", fontWeight: "700" },
  { tag: t.string, color: "#9ece6a" },
  { tag: t.comment, color: "#6b7280", fontStyle: "italic" },
  { tag: t.meta, color: "#e0af68" },
  { tag: t.typeName, color: "#7dcfff" },
  { tag: t.number, color: "#ff9e64" },
  { tag: t.operator, color: "#89ddff" },
]);

const theme = EditorView.theme(
  {
    "&": { backgroundColor: "var(--bg)", color: "var(--text)", fontSize: "13px", border: "1px solid var(--border)", borderRadius: "4px" },
    ".cm-content": { fontFamily: "var(--mono)", caretColor: "var(--text-strong)" },
    ".cm-gutters": { backgroundColor: "var(--panel)", color: "var(--muted)", border: "none" },
    ".cm-activeLine": { backgroundColor: "#ffffff08" },
    ".cm-activeLineGutter": { backgroundColor: "#ffffff0d" },
    "&.cm-focused": { outline: "2px solid var(--focus)" },
    ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "#3b4a6b !important" },
  },
  { dark: true },
);

interface Props {
  value: string;
  onChange?: (value: string) => void;
  problems?: Problem[];
  readOnly?: boolean;
  minHeight?: string;
  label: string;
}

/** CodeMirror 6 editor for Cedar with server-reported problems as inline diagnostics. */
export function CedarEditor({ value, onChange, problems = [], readOnly = false, minHeight = "320px", label }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    const extensions: Extension[] = [
      lineNumbers(),
      lintGutter(),
      history(),
      drawSelection(),
      highlightActiveLine(),
      bracketMatching(),
      cedarLanguage,
      syntaxHighlighting(highlight),
      theme,
      EditorView.theme({ ".cm-scroller": { minHeight } }),
      keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
      linter(null),
      EditorView.contentAttributes.of({ "aria-label": label }),
      EditorState.readOnly.of(readOnly),
      EditorView.updateListener.of((u) => {
        if (u.docChanged && !u.transactions.some((tr) => tr.annotation(External))) onChangeRef.current?.(u.state.doc.toString());
      }),
    ];
    view.current = new EditorView({ state: EditorState.create({ doc: value, extensions }), parent: host.current! });
    return () => view.current?.destroy();
    // The editor is created once; value changes from outside are applied below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readOnly]);

  useEffect(() => {
    const v = view.current;
    if (v && v.state.doc.toString() !== value) {
      v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value }, annotations: External.of(true) });
    }
  }, [value]);

  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const doc = v.state.doc;
    const diagnostics: Diagnostic[] = problems.map((p) => {
      const line = p.line && p.line >= 1 && p.line <= doc.lines ? doc.line(p.line) : doc.line(1);
      return { from: line.from, to: line.to, severity: p.severity === "warning" ? "warning" : "error", message: (p.policyId ? `${p.policyId}: ` : "") + p.message };
    });
    v.dispatch(setDiagnostics(v.state, diagnostics));
  }, [problems]);

  return <div ref={host} className="cedar-editor" />;
}

/** Inserts text at the end of an editor value with a separating blank line. */
export function appendSnippet(current: string, snippet: string): string {
  return current.replace(/\s*$/, "") + (current.trim() ? "\n\n" : "") + snippet + "\n";
}

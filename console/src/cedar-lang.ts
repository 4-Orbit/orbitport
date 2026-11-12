import { StreamLanguage, type StreamParser } from "@codemirror/language";

/** Minimal Cedar highlighter: keywords, effects, annotations, strings, entity refs, comments. */
const KEYWORDS = new Set(["when", "unless", "principal", "action", "resource", "context", "in", "is", "has", "like", "if", "then", "else", "true", "false"]);
const EFFECTS = new Set(["permit", "forbid"]);

const parser: StreamParser<{ inString: boolean }> = {
  startState: () => ({ inString: false }),
  token(stream, state) {
    if (state.inString) {
      while (!stream.eol()) {
        const ch = stream.next();
        if (ch === "\\") stream.next();
        else if (ch === '"') {
          state.inString = false;
          break;
        }
      }
      return "string";
    }
    if (stream.eatSpace()) return null;
    if (stream.match("//")) {
      stream.skipToEnd();
      return "comment";
    }
    if (stream.peek() === '"') {
      stream.next();
      state.inString = true;
      return "string";
    }
    if (stream.match(/^@[A-Za-z_]\w*/)) return "meta";
    if (stream.match(/^[A-Z][A-Za-z0-9_]*(?=::)/)) return "typeName";
    if (stream.match("::")) return "punctuation";
    if (stream.match(/^-?\d+/)) return "number";
    const word = stream.match(/^[A-Za-z_][A-Za-z0-9_]*/) as RegExpMatchArray | null;
    if (word) {
      if (EFFECTS.has(word[0])) return "keyword strong";
      if (KEYWORDS.has(word[0])) return "keyword";
      return "variableName";
    }
    if (stream.match(/^(==|!=|<=|>=|&&|\|\||[<>!+\-*])/)) return "operator";
    stream.next();
    return null;
  },
};

export const cedarLanguage = StreamLanguage.define(parser);

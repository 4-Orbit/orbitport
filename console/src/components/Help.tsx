import { useId, useState, type ReactNode } from "react";
import { GLOSSARY, type GlossaryKey } from "../glossary.ts";

/**
 * A glossary term with an explanation on hover or keyboard focus. The text is
 * also exposed to screen readers through aria-describedby.
 */
export function Term({ k, children }: { k: GlossaryKey; children?: ReactNode }) {
  const id = useId();
  const entry = GLOSSARY[k];
  return (
    <span className="term" tabIndex={0} aria-describedby={id}>
      {children ?? entry.term.toLowerCase()}
      <span role="tooltip" id={id} className="term-tip">
        <strong>{entry.term}.</strong> {entry.short}
      </span>
    </span>
  );
}

const introKey = (page: string) => `orbitport-console-intro-hidden-${page}`;

function hidden(page: string): boolean {
  try {
    return localStorage.getItem(introKey(page)) === "1";
  } catch {
    return false;
  }
}

/**
 * A short explanation at the top of a page. It can be collapsed; the choice is
 * remembered per page in this browser, and "Show tip" brings it back.
 */
export function Intro({ page, title, children }: { page: string; title: string; children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(() => hidden(page));
  const set = (v: boolean) => {
    setCollapsed(v);
    try {
      localStorage.setItem(introKey(page), v ? "1" : "0");
    } catch {
      // per-viewer preference only
    }
  };
  if (collapsed) {
    return (
      <button type="button" className="intro-show link-button" onClick={() => set(false)}>
        ⓘ What is this page?
      </button>
    );
  }
  return (
    <section className="intro" aria-label={`About ${title}`}>
      <div className="intro-body">
        <strong>{title}</strong>
        <div>{children}</div>
      </div>
      <div className="intro-actions">
        <a href="#/help">How the console works</a>
        <button type="button" className="link-button" onClick={() => set(true)}>
          Hide tip
        </button>
      </div>
    </section>
  );
}

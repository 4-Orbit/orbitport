/** "Keys 1–50 of 236 · ‹ Previous · Next ›" for offset-paged lists. */
export function Pager({ label, offset, pageSize, total, onChange }: { label: string; offset: number; pageSize: number; total: number; onChange: (offset: number) => void }) {
  if (total <= pageSize && offset === 0) return null;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + pageSize, total);
  return (
    <nav className="pager" aria-label={`${label} pages`}>
      <span className="muted small">
        {label} {from}–{to} of {total}
      </span>
      <button type="button" className="button small" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - pageSize))}>
        ‹ Previous
      </button>
      <button type="button" className="button small" disabled={to >= total} onClick={() => onChange(offset + pageSize)}>
        Next ›
      </button>
    </nav>
  );
}

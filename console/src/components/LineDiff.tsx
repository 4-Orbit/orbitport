/** Small LCS line diff for comparing policy texts. */
export interface DiffLine {
  kind: "same" | "add" | "del";
  text: string;
}

export function diffLines(a: string, b: string): DiffLine[] {
  const x = a.split("\n");
  const y = b.split("\n");
  const n = x.length;
  const m = y.length;
  if (n * m > 4_000_000) return [...x.map((t) => ({ kind: "del" as const, text: t })), ...y.map((t) => ({ kind: "add" as const, text: t }))];
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ kind: "same", text: x[i++] });
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ kind: "del", text: x[i++] });
    else out.push({ kind: "add", text: y[j++] });
  }
  while (i < n) out.push({ kind: "del", text: x[i++] });
  while (j < m) out.push({ kind: "add", text: y[j++] });
  return out;
}

export function LineDiff({ before, after }: { before: string; after: string }) {
  const lines = diffLines(before, after);
  if (lines.every((l) => l.kind === "same")) return <p className="muted">Policy text is identical.</p>;
  return (
    <pre className="line-diff">
      {lines.map((l, i) => (
        <div key={i} className={`dl dl-${l.kind}`}>
          <span className="dl-sign">{l.kind === "add" ? "+" : l.kind === "del" ? "-" : " "}</span>
          {l.text || " "}
        </div>
      ))}
    </pre>
  );
}

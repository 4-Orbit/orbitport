import type { Cell, MatrixResult } from "../types.ts";
import { DecisionBadge, PolicyChips } from "./Badges.tsx";
import { useState } from "react";

const short = (action: string) => action.replace(/^kms\./, "");

/** One table per principal: keys as rows, actions as columns. Click a cell to see why. */
export function MatrixGrid({ matrix, onCell }: { matrix: MatrixResult; onCell?: (cell: Cell) => void }) {
  const [picked, setPicked] = useState<Cell | null>(null);
  const index = new Map(matrix.cells.map((c) => [`${c.principal}|${c.resource}|${c.action}`, c]));
  return (
    <div className="matrix">
      {matrix.principals.map((p) => {
        const name = p || "(account)";
        const roles = p ? matrix.agentRoles[p] ?? [] : [];
        return (
          <section key={name} className="panel matrix-agent">
            <header className="panel-head">
              <h2 className="mono">{name}</h2>
              <span className="muted small">{p ? (roles.length ? `roles: ${roles.join(", ")}` : "no roles") : "account-level credential (platform.owner)"}</span>
            </header>
            <div className="table-wrap">
              <table className="matrix-table">
                <thead>
                  <tr>
                    <th>Key</th>
                    {matrix.actions.map((a) => (
                      <th key={a} title={a}>
                        {short(a)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {matrix.keys.map((k) => (
                    <tr key={k}>
                      <td className="mono">{k}</td>
                      {matrix.actions.map((a) => {
                        const c = index.get(`${name}|${k}|${a}`);
                        if (!c) return <td key={a} />;
                        return (
                          <td key={a}>
                            <button
                              type="button"
                              className={`cell cell-${c.decision.toLowerCase()}`}
                              aria-label={`${name} ${a} ${k}: ${c.decision}`}
                              onClick={() => {
                                setPicked(c);
                                onCell?.(c);
                              }}
                            >
                              {c.decision === "ALLOW" ? "ALLOW" : "·"}
                            </button>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
      {picked && (
        <div className="panel cell-explain" role="status">
          <span className="mono">{picked.principal}</span> · <span className="mono">{picked.action}</span> · <span className="mono">{picked.resource}</span> → <DecisionBadge decision={picked.decision} />{" "}
          <PolicyChips ids={picked.determiningPolicies} />
        </div>
      )}
    </div>
  );
}

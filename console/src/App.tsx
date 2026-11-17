import { useEffect, useState } from "react";
import { api, getHealth } from "./api.ts";
import { usePolling } from "./usePolling.ts";
import { useRoute, type Page } from "./route.ts";
import { ActivityPage } from "./pages/ActivityPage.tsx";
import { AccessPage } from "./pages/AccessPage.tsx";
import { PoliciesPage } from "./pages/PoliciesPage.tsx";
import { SimulatePage } from "./pages/SimulatePage.tsx";
import { TestsPage } from "./pages/TestsPage.tsx";
import { VersionsPage } from "./pages/VersionsPage.tsx";
import { AgentsPage } from "./pages/AgentsPage.tsx";

const TABS: { page: Page; label: string }[] = [
  { page: "activity", label: "Activity" },
  { page: "access", label: "Access" },
  { page: "policies", label: "Policies" },
  { page: "simulate", label: "Simulate" },
  { page: "tests", label: "Tests" },
  { page: "versions", label: "Versions" },
  { page: "agents", label: "Agents" },
];

export function App() {
  const route = useRoute();
  const health = usePolling(getHealth, 10000);
  const [activeVersion, setActiveVersion] = useState<number | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    api
      .active()
      .then((a) => setActiveVersion(a.version?.version ?? null))
      .catch(() => setActiveVersion(null));
  }, [tick, health.updatedAt]);

  const h = health.data;
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-name">Orbitport</span>
          <span className="brand-sub">Console · 4Orbit policy playground</span>
        </div>
        <nav className="tabs">
          {TABS.map((t) => (
            <a key={t.page} href={`#/${t.page}`} aria-current={route.page === t.page ? "page" : undefined}>
              {t.label}
            </a>
          ))}
        </nav>
        <div className="topbar-status">
          <span className="muted">
            Active policy <span className="mono">{activeVersion ? `v${activeVersion}` : "none"}</span>
          </span>
          {h && (
            <span className="muted" title={h.gatewayUrl}>
              Gateway <span className={`dot ${h.gateway === "ok" ? "dot-ok" : "dot-bad"}`} aria-hidden /> {h.gateway}
            </span>
          )}
        </div>
      </header>

      {health.error && <div className="banner banner-error">Console server unreachable ({health.error}).</div>}
      {h && !h.tokenPresent && (
        <div className="banner banner-error">
          Operator token missing. Run <code>make 4orbit-seed</code> from the orbitport checkout.
        </div>
      )}
      {h && h.tokenPresent && h.gateway !== "ok" && <div className="banner banner-error">Gateway unreachable at {h.gatewayUrl}. Is the stack running (make 4orbit-ps)?</div>}

      <main className="content">
        {route.page === "activity" && <ActivityPage selectedId={route.requestId} />}
        {route.page === "access" && <AccessPage />}
        {route.page === "policies" && <PoliciesPage />}
        {route.page === "simulate" && <SimulatePage />}
        {route.page === "tests" && <TestsPage />}
        {route.page === "versions" && <VersionsPage onActivated={() => setTick((x) => x + 1)} />}
        {route.page === "agents" && <AgentsPage />}
      </main>
    </div>
  );
}

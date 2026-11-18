import { GLOSSARY } from "../glossary.ts";

/** "How the console works": the one page someone new should read. */
export function HelpPage() {
  return (
    <div className="help-page">
      <section className="panel help-section">
        <header className="panel-head">
          <h2>How the console works</h2>
        </header>
        <div className="panel-body prose">
          <p>
            This console controls what your <strong>AI agents</strong> may do with your <strong>encryption keys</strong>. Every time an agent asks the KMS to encrypt, sign or rotate,
            the KMS checks your rules first. If no rule allows the request, it's denied and the key is never touched.
          </p>
          <p>You never edit what's enforced directly. Changes move through three stages:</p>

          <ol className="stages" aria-label="Draft, version, active">
            <li className="stage">
              <span className="stage-num">1</span>
              <strong>Draft</strong>
              <span>Your working copy on the Policies page. It's only in this browser and isn't enforced. Undo is available.</span>
              <em>Policies → edit rules</em>
            </li>
            <li className="stage-arrow" aria-hidden>
              → Save as new version →
            </li>
            <li className="stage">
              <span className="stage-num">2</span>
              <strong>Saved version</strong>
              <span>A permanent, numbered snapshot (v1, v2, …). Saving is safe: it doesn't change what's enforced.</span>
              <em>Versions → list, compare</em>
            </li>
            <li className="stage-arrow" aria-hidden>
              → Activate →
            </li>
            <li className="stage">
              <span className="stage-num">3</span>
              <strong>Active version</strong>
              <span>The single version the KMS enforces, within about 5 seconds of activating. Roll back by activating an older one.</span>
              <em>Versions → Activate</em>
            </li>
          </ol>

          <p className="callout">
            <strong>Saving never changes enforcement; only Activate does.</strong> And loading something into the editor never saves anything: “Start from active” and “Start
            from 4Orbit template” only replace your draft (and you can Undo).
          </p>
        </div>
      </section>

      <section className="panel help-section">
        <header className="panel-head">
          <h2>Making a change, step by step</h2>
        </header>
        <div className="panel-body prose">
          <ol>
            <li>
              <strong>Policies:</strong> add or edit a rule in <em>Plain language</em> (a form: who, can, on which keys, until when) or in <em>Cedar code</em>. Both edit the same
              draft; switch any time.
            </li>
            <li>
              <strong>Check the impact:</strong> the status strip shows how many decisions your draft changes compared with what's active. “What changes vs active?” lists them
              (“deployment-agent · Sign · prod-key: DENY → ALLOW”).
            </li>
            <li>
              <strong>Try it:</strong> on <em>Simulate</em>, ask about any agent, action and key, against your draft, even at a future date. Save interesting answers as tests.
            </li>
            <li>
              <strong>Save as new version</strong> with a short message. If an identical version already exists, the console tells you instead of creating a copy.
            </li>
            <li>
              <strong>Versions → Activate.</strong> Your tests run first; if any fail, activation is refused and the failing cases are listed.
            </li>
            <li>
              <strong>Watch:</strong> <em>Activity</em> shows every real request, which rule decided it, and which version was active.
            </li>
          </ol>
        </div>
      </section>

      <section className="panel help-section">
        <header className="panel-head">
          <h2>Safety nets</h2>
        </header>
        <div className="panel-body prose">
          <ul>
            <li>
              <strong>Undo / Redo</strong> (⌘Z / ⇧⌘Z) for every draft change, including deletes and loads. Deleting a rule, role or agent asks first and says what it affects.
            </li>
            <li>
              <strong>Tests</strong> stop a version that breaks your expectations from being activated.
            </li>
            <li>
              <strong>Rollback:</strong> versions are never deleted, so activating an older one undoes an activation.
            </li>
            <li>
              <strong>Platform rules</strong> always apply: your own account token keeps full access (so you can't lock yourself out), tenants are isolated, and agents can never
              change policy.
            </li>
            <li>
              <strong>Default deny:</strong> an agent can do nothing until a rule allows it, and a “Blocks” rule beats any “Allows” rule.
            </li>
            <li>
              <strong>Why was this denied?</strong> Every DENY says why (blocked, expired, the closest rule and what it needs, or no rule at all), and <strong>Grant this…</strong>{" "}
              prepares the fix in your draft: a rule for just that agent first, since it grants the least. Nothing is enforced until you save and activate.
            </li>
          </ul>
        </div>
      </section>

      <section className="panel help-section">
        <header className="panel-head">
          <h2>The tabs</h2>
        </header>
        <div className="table-wrap">
          <table className="help-table">
            <tbody>
              <tr>
                <th scope="row">Activity</th>
                <td>Every real decision: who asked, what, on which key, allowed or denied, and why.</td>
              </tr>
              <tr>
                <th scope="row">Access</th>
                <td>A grid of every agent × key × action: who can do what, for the active version, your draft or any saved version.</td>
              </tr>
              <tr>
                <th scope="row">Policies</th>
                <td>Edit your draft: rules (plain language or Cedar), agents and roles. Save it as a version.</td>
              </tr>
              <tr>
                <th scope="row">Simulate</th>
                <td>
                  Ask “would this request be allowed?” without calling the KMS. Supports future dates. <strong>Run it for real</strong> then sends the same request to the KMS as the
                  agent and shows whether enforcement agrees.
                </td>
              </tr>
              <tr>
                <th scope="row">Tests</th>
                <td>Saved expectations that must keep passing before a version can be activated.</td>
              </tr>
              <tr>
                <th scope="row">Versions</th>
                <td>Every saved version: compare, activate, roll back, or open one in the editor.</td>
              </tr>
              <tr>
                <th scope="row">Agents</th>
                <td>Registered agents and their roles. Mint short-lived agent tokens here.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel help-section" id="glossary">
        <header className="panel-head">
          <h2>Glossary</h2>
        </header>
        <dl className="glossary panel-body">
          {Object.values(GLOSSARY).map((g) => (
            <div key={g.term}>
              <dt>{g.term}</dt>
              <dd>{g.short}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}

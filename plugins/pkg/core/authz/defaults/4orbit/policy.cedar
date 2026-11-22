// 4Orbit demo organization, ported from 4orbit prototype-1/policies/policy.cedar.
//
// Developers may encrypt with demo-key until it expires and with dev-key.
// Security agents may rotate every demo key. Deployment agents may encrypt
// with prod-key. Everything else is denied by default.
//
// `use` in Prototype 1 meant exactly `encrypt` (D-013), so these grants name
// kms.Encrypt. Write `action in Action::"use"` to grant the whole use group.

// Time-limited (US5): context.currentTime is trusted plugin time in Unix
// epoch seconds. The grant holds while currentTime < 1800000000
// (2027-01-15T08:00:00Z) and is denied at and after that instant.
@id("developer-encrypt-demo-key")
permit (
  principal in Role::"developer",
  action == Action::"kms.Encrypt",
  resource == Key::"demo-key"
)
when { context.currentTime < 1800000000 };

@id("security-rotate-demo-key")
permit (
  principal in Role::"security",
  action == Action::"kms.RotateKey",
  resource == Key::"demo-key"
);

@id("developer-encrypt-dev-key")
permit (
  principal in Role::"developer",
  action == Action::"kms.Encrypt",
  resource == Key::"dev-key"
);

@id("security-rotate-dev-key")
permit (
  principal in Role::"security",
  action == Action::"kms.RotateKey",
  resource == Key::"dev-key"
);

@id("security-rotate-prod-key")
permit (
  principal in Role::"security",
  action == Action::"kms.RotateKey",
  resource == Key::"prod-key"
);

@id("deployment-encrypt-prod-key")
permit (
  principal in Role::"deployment",
  action == Action::"kms.Encrypt",
  resource == Key::"prod-key"
);

// Mock repository only. A real repository needs its own explicit grant.
@id("developer-create-demo-issue")
permit (
  principal in Role::"developer",
  action == Action::"github.issue.Create",
  resource == Repository::"demo-owner/orbitport-test"
);

// Developers may read the mock repository, but never anything under secrets/.
@id("developer-read-demo-repo")
permit (
  principal in Role::"developer",
  action == Action::"github.contents.Read",
  resource == Repository::"demo-owner/orbitport-test"
)
unless { context.path like "secrets/*" };

// Developers may comment on issues and pull requests in the mock repository.
@id("developer-comment-demo-repo")
permit (
  principal in Role::"developer",
  action == Action::"github.issue.Comment",
  resource == Repository::"demo-owner/orbitport-test"
);

// Developers may create branches, but only in their own agent/<agent-id>/
// namespace. (Agents can never write the default branch: a platform rule.)
@id("developer-own-branches")
permit (
  principal in Role::"developer",
  action == Action::"github.branch.Create",
  resource == Repository::"demo-owner/orbitport-test"
)
when { context has branchAgent && context.branchAgent == principal };

// Developers may commit to their own agent/<agent-id>/ branches, never to
// workflow files (which run with the repository's CI permissions).
@id("developer-commit-own-branches")
permit (
  principal in Role::"developer",
  action == Action::"github.commit.Create",
  resource == Repository::"demo-owner/orbitport-test"
)
when { context has branchAgent && context.branchAgent == principal }
unless { context.touchesWorkflows };

// Developers may open pull requests from their own agent/<agent-id>/ branches.
@id("developer-propose-own-branches")
permit (
  principal in Role::"developer",
  action == Action::"github.pr.Create",
  resource == Repository::"demo-owner/orbitport-test"
)
when { context has headAgent && context.headAgent == principal };

// Security agents review pull requests (comment or request changes).
// Approval stays with people: GitHub doesn't let the App approve its own
// pull requests, and every agent acts as the App.
@id("security-review-demo-repo")
permit (
  principal in Role::"security",
  action == Action::"github.pr.Review",
  resource == Repository::"demo-owner/orbitport-test"
)
when { context.event != "APPROVE" };

// No agent reviews its own pull request.
@id("no-agent-reviews-own-pull")
forbid (
  principal is Agent,
  action == Action::"github.pr.Review",
  resource
)
when { context has headAgent && context.headAgent == principal };

// Deployment agents merge pull requests into the default branch, only once a
// person has approved the current head and GitHub reports it mergeable with
// passing checks ("clean").
@id("deployment-merge-approved")
permit (
  principal in Role::"deployment",
  action == Action::"github.pr.Merge",
  resource == Repository::"demo-owner/orbitport-test"
)
when { context.humanApprovals >= 1 && context.mergeableState == "clean" };

// No agent merges its own pull request.
@id("no-agent-merges-own-pull")
forbid (
  principal is Agent,
  action == Action::"github.pr.Merge",
  resource
)
when { context has headAgent && context.headAgent == principal };

// Any agent may read pull request metadata (state, head commit, approvals),
// which reviewing and merging need.
@id("agents-read-pull-requests")
permit (
  principal is Agent,
  action == Action::"github.pr.Get",
  resource == Repository::"demo-owner/orbitport-test"
);

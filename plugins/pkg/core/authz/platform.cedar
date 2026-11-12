// Platform policy. Embedded in every enforcing plugin and evaluated together
// with the tenant's own policy set. Tenants cannot edit or remove it.

// An account-level credential (a PAT with no agent_id) keeps today's
// behaviour: full control of its own tenant (D-030).
@id("platform.owner")
permit (principal is Account, action, resource)
when { principal.tenant == resource.tenant };

// No principal ever reaches another tenant's resources, whatever a tenant
// policy says. forbid always overrides permit.
@id("platform.tenant-fence")
forbid (principal, action, resource)
unless { principal.tenant == resource.tenant };

// Agents can never read, change, simulate or mint tokens through the policy
// administration API. Policy tampering by an agent is ruled out here.
@id("platform.agents-never-administer-policy")
forbid (principal is Agent, action in Action::"policy", resource);

import { createWorkflow } from './workflow.mjs';
import { githubApp } from './github.mjs';

/**
 * Wiring boundary for the team's implementations, not an invented upstream API.
 * Supply authenticated, scope-aware validation, policy evaluation, and durable audit.
 * No local credential or mock fallback is permitted here.
 */
export function connectSpaceComputer({ repository, credentials, policy, audit, app }) {
  if (typeof credentials?.validate !== 'function' || typeof policy?.authorize !== 'function' || typeof audit?.append !== 'function') {
    throw new Error('Credential, policy and audit interfaces are required');
  }
  return createWorkflow({ repository,
    validateCredential: (token, scope) => credentials.validate(token, scope),
    authorize: request => policy.authorize(request),
    audit: record => audit.append(record),
    github: githubApp({ ...app, repository }),
  });
}

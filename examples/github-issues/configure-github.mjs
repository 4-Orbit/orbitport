import { readFileSync } from 'node:fs';
import { verifyInstallation } from './github.mjs';

// Print installation metadata only. Never print keys, JWTs, tokens, or provider errors.
try {
  const result = await verifyInstallation({ appId: process.env.GITHUB_APP_ID,
    privateKey: readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, 'utf8'), repository: process.env.GITHUB_TEST_REPOSITORY });
  console.log(JSON.stringify(result));
} catch {
  console.error('Installation check failed. Check the key path, App ID, selected repository, and Issues write permission.');
  process.exitCode = 1;
}

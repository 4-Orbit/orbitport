import { STATUS_CODES } from 'node:http';

const endpoint = 'https://generativelanguage.googleapis.com/v1beta/interactions';
const messages = {
  overloaded: 'Gemini is temporarily overloaded (HTTP 503). Try again later or choose another model.',
  timeout: 'Gemini timed out. Try again later or choose another model.',
  auth: 'Gemini rejected the API key. Check GEMINI_API_KEY.',
  quota: 'Gemini rate limit or quota reached (HTTP 429).',
  request: 'Gemini rejected the request. Check GEMINI_MODEL.',
  network: 'Gemini could not be reached.',
  response: 'Gemini returned an invalid response.',
  proposal: 'Gemini did not propose one valid issue.',
};

export class GeminiError extends Error {
  constructor(kind, httpStatus) {
    super(Number.isInteger(httpStatus) ? `Gemini API HTTP ${httpStatus} ${STATUS_CODES[httpStatus] || 'Error'}` : messages[kind]);
    this.kind = kind;
    this.httpStatus = Number.isInteger(httpStatus) ? httpStatus : null;
  }
}

/** Gemini only proposes tool arguments. The caller owns identity, policy, and execution. */
export function createGeminiClient({ apiKey, model = 'gemini-3.5-flash-lite', fetchImpl = fetch, waitImpl = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  if (typeof apiKey !== 'string' || !apiKey.trim()) throw new Error('Gemini API key is required');
  if (typeof model !== 'string' || !/^gemini-[a-z0-9.-]+$/.test(model)) throw new Error('Invalid Gemini model');
  return {
    async proposeIssue({ prompt, repository }) {
      if (typeof prompt !== 'string' || !prompt.trim() || prompt.length > 4000 ||
        typeof repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error('Invalid Gemini task');
      const request = {
        model,
        store: false,
        input: `Create exactly one useful GitHub issue for ${repository} based on this operator task. Use the create_issue tool.\n\nTask: ${prompt}`,
        tools: [{
          type: 'function', name: 'create_issue', description: 'Propose the title and body for one GitHub issue. The server will decide whether it may be created.',
          parameters: { type: 'object', properties: {
            title: { type: 'string', description: 'Concise issue title' },
            body: { type: 'string', description: 'Issue description with context and acceptance criteria' },
          }, required: ['title', 'body'] },
        }],
      };
      let response;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          response = await fetchImpl(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
            body: JSON.stringify(request), redirect: 'error', signal: AbortSignal.timeout(30_000) });
        } catch (error) { throw new GeminiError(error?.name === 'TimeoutError' ? 'timeout' : 'network'); }
        if (response.status !== 503 || attempt === 1) break;
        await waitImpl(750);
      }
      if (!response.ok) throw new GeminiError(response.status === 503 ? 'overloaded' :
        [401, 403].includes(response.status) ? 'auth' : response.status === 429 ? 'quota' : 'request', response.status);
      let data;
      try { data = await response.json(); } catch { throw new GeminiError('response'); }
      const calls = data?.steps?.filter(step => step?.type === 'function_call') ?? [];
      if (calls.length !== 1 || calls[0].name !== 'create_issue') throw new GeminiError('proposal');
      const args = calls[0].arguments;
      if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).some(key => !['title', 'body'].includes(key)) ||
        typeof args.title !== 'string' || !args.title.trim() || args.title.length > 256 ||
        typeof args.body !== 'string' || args.body.length > 16_384) throw new GeminiError('proposal');
      return { title: args.title, body: args.body };
    },
  };
}

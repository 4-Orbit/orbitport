import { STATUS_CODES } from "node:http";

const ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/interactions";
const DEFAULT_MODEL = "gemini-3.5-flash-lite";
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export type GeminiErrorKind = "timeout" | "network" | "response" | "proposal" | "provider";

const messages: Record<GeminiErrorKind, string> = {
  timeout: "Gemini timed out before an HTTP response.",
  network: "Gemini could not be reached.",
  response: "Gemini returned an invalid response.",
  proposal: "Gemini did not propose one valid issue.",
  provider: "Gemini rejected the request.",
};

export class GeminiError extends Error {
  constructor(readonly kind: GeminiErrorKind, readonly httpStatus: number | null = null) {
    super(httpStatus === null ? messages[kind] : `Gemini API HTTP ${httpStatus} ${STATUS_CODES[httpStatus] || "Error"}`);
  }
}

export interface GeminiIssueProposal { title: string; body: string }
export interface GeminiIssueClient {
  proposeIssue(input: { prompt: string; repository: string }): Promise<GeminiIssueProposal>;
}

export function createGeminiClient({
  apiKey,
  model = DEFAULT_MODEL,
  fetchImpl = fetch,
  waitImpl = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
}: {
  apiKey: string;
  model?: string;
  fetchImpl?: typeof fetch;
  waitImpl?: (ms: number) => Promise<void>;
}): GeminiIssueClient {
  if (!apiKey?.trim()) throw new Error("Gemini API key is required");
  if (!/^gemini-[a-z0-9.-]+$/.test(model)) throw new Error("Invalid Gemini model");
  return {
    async proposeIssue({ prompt, repository }) {
      if (!prompt?.trim() || prompt.length > 4_000 || !REPOSITORY.test(repository)) throw new GeminiError("proposal");
      const request = {
        model,
        store: false,
        input: `Create exactly one useful GitHub issue for ${repository} based on this operator task. Use the create_issue tool.\n\nTask: ${prompt}`,
        tools: [{
          type: "function", name: "create_issue",
          description: "Propose a title and body for one GitHub issue. The server decides whether it may be created.",
          parameters: { type: "object", properties: {
            title: { type: "string", description: "Concise issue title" },
            body: { type: "string", description: "Issue description and acceptance criteria" },
          }, required: ["title", "body"] },
        }],
      };
      let response: Response | undefined;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          response = await fetchImpl(ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
            body: JSON.stringify(request),
            redirect: "error",
            signal: AbortSignal.timeout(30_000),
          });
        } catch (error) {
          throw new GeminiError(error instanceof Error && error.name === "TimeoutError" ? "timeout" : "network");
        }
        if (response.status !== 503 || attempt === 1) break;
        await waitImpl(750);
      }
      if (!response) throw new GeminiError("network");
      if (!response.ok) throw new GeminiError("provider", response.status);
      let data: { steps?: Array<{ type?: unknown; name?: unknown; arguments?: unknown }> };
      try { data = await response.json() as typeof data; } catch { throw new GeminiError("response"); }
      if (!Array.isArray(data?.steps)) throw new GeminiError("response");
      const calls = data.steps.filter((step) => step?.type === "function_call");
      if (calls.length !== 1 || calls[0].name !== "create_issue") throw new GeminiError("proposal");
      const args = calls[0].arguments;
      if (!args || typeof args !== "object" || Array.isArray(args)) throw new GeminiError("proposal");
      const issue = args as Record<string, unknown>;
      if (Object.keys(issue).some((key) => !["title", "body"].includes(key)) ||
        typeof issue.title !== "string" || !issue.title.trim() || issue.title.length > 256 ||
        typeof issue.body !== "string" || issue.body.length > 16_384) throw new GeminiError("proposal");
      return { title: issue.title, body: issue.body };
    },
  };
}

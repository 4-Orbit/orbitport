/**
 * The GitHub tools a Gemini agent may call. Each tool is exactly one
 * github.* gateway method, sent with the agent's own token, so the GitHub
 * plugin's Cedar check decides every step. The repository and agent are
 * fixed by the operator for the whole run; a tool can't choose them.
 */

export interface ToolScope {
  repository: string;
  agentId: string;
}

export interface GithubTool {
  name: string;
  description: string;
  /** JSON schema of the arguments Gemini supplies. */
  parameters: Record<string, unknown>;
  method: string;
  /** Gateway params, or a message explaining why the arguments are invalid. */
  params: (args: Record<string, unknown>, scope: ToolScope) => Record<string, unknown> | string;
  /** A short description of the call for the run log; never file contents. */
  summary: (args: Record<string, unknown>) => string;
}

const str = (v: unknown, max: number): v is string => typeof v === "string" && v.length <= max;
const int = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v > 0;
const only = (args: Record<string, unknown>, keys: string[]) => Object.keys(args).every((k) => keys.includes(k));

export const GITHUB_TOOLS: GithubTool[] = [
  {
    name: "create_issue",
    description: "Create one issue in the repository.",
    parameters: {
      type: "object",
      properties: { title: { type: "string", description: "Concise issue title" }, body: { type: "string", description: "Issue description" } },
      required: ["title", "body"],
    },
    method: "github.issue.Create",
    params: (a, s) => {
      if (!only(a, ["title", "body"]) || !str(a.title, 256) || !a.title.trim() || !str(a.body, 16_384)) return "title (1–256 characters) and body (up to 16384) are required";
      return { repository: s.repository, title: a.title, body: a.body };
    },
    summary: (a) => `issue “${String(a.title ?? "").slice(0, 80)}”`,
  },
];

const readTool = (name: string, description: string): GithubTool => ({
  name,
  description,
  parameters: {
    type: "object",
    properties: {
      path: { type: "string", description: name === "read_file" ? "File path relative to the repository root" : "Directory path relative to the root; empty for the root" },
      ref: { type: "string", description: "Branch, tag or commit to read; omit for the default branch" },
    },
    required: name === "read_file" ? ["path"] : [],
  },
  method: "github.contents.Read",
  params: (a, s) => {
    if (!only(a, ["path", "ref"]) || (a.path !== undefined && !str(a.path, 512)) || (a.ref !== undefined && !str(a.ref, 255))) return "path (up to 512 characters) and an optional ref";
    if (name === "read_file" && !a.path) return "path is required";
    return { repository: s.repository, path: a.path ?? "", ...(a.ref ? { ref: a.ref } : {}) };
  },
  summary: (a) => `${name === "read_file" ? "read" : "list"} ${a.path || "/"}${a.ref ? ` @ ${a.ref}` : ""}`,
});

GITHUB_TOOLS.push(
  readTool("read_file", "Read one file. Returns its text content."),
  readTool("list_directory", "List the files and folders in a directory."),
  {
    name: "comment_on_issue",
    description: "Add a comment to an existing issue.",
    parameters: {
      type: "object",
      properties: { number: { type: "integer", description: "Issue number" }, body: { type: "string", description: "Comment text (Markdown)" } },
      required: ["number", "body"],
    },
    method: "github.issue.Comment",
    params: (a, s) => {
      if (!only(a, ["number", "body"]) || !int(a.number) || !str(a.body, 16_384) || !a.body.trim()) return "number (a positive integer) and body (1–16384 characters) are required";
      return { repository: s.repository, number: a.number, body: a.body };
    },
    summary: (a) => `comment on #${String(a.number)}`,
  },
);

export const toolByName = (name: string) => GITHUB_TOOLS.find((t) => t.name === name);

/** Helpers shared by tools added later. */
export const toolArgs = { str, int, only };

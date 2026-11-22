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
  {
    name: "create_branch",
    description: "Create a branch from the default branch (or from another branch or commit). Name it agent/<your-agent-id>/<short-name>.",
    parameters: {
      type: "object",
      properties: { branch: { type: "string", description: "New branch name" }, from: { type: "string", description: "Branch or commit to start from; omit for the default branch" } },
      required: ["branch"],
    },
    method: "github.branch.Create",
    params: (a, s) => {
      if (!only(a, ["branch", "from"]) || !str(a.branch, 255) || !a.branch || (a.from !== undefined && !str(a.from, 255))) return "branch (up to 255 characters) and an optional from";
      return { repository: s.repository, branch: a.branch, ...(a.from ? { from: a.from } : {}) };
    },
    summary: (a) => `branch ${String(a.branch)}${a.from ? ` from ${String(a.from)}` : ""}`,
  },
  {
    name: "commit_files",
    description:
      "Commit file changes to an existing branch you created (one commit). Give each changed file's complete new content. At most 20 files and 48000 characters of content.",
    parameters: {
      type: "object",
      properties: {
        branch: { type: "string", description: "Branch to commit to" },
        message: { type: "string", description: "Commit message" },
        files: {
          type: "array",
          description: "Files to add or replace, with their complete new content",
          items: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"] },
        },
        deletes: { type: "array", description: "Paths of files to delete", items: { type: "string" } },
      },
      required: ["branch", "message"],
    },
    method: "github.commit.Create",
    params: (a, s) => {
      if (!only(a, ["branch", "message", "files", "deletes"]) || !str(a.branch, 255) || !a.branch || !str(a.message, 2000) || !a.message.trim()) return "branch, message (1–2000 characters) and files or deletes";
      const files = a.files === undefined ? [] : a.files;
      const deletes = a.deletes === undefined ? [] : a.deletes;
      if (!Array.isArray(files) || !Array.isArray(deletes) || files.length + deletes.length === 0 || files.length + deletes.length > 20) return "between 1 and 20 file changes";
      for (const f of files) if (!f || typeof f !== "object" || !only(f as Record<string, unknown>, ["path", "content"]) || !str((f as Record<string, unknown>).path, 512) || typeof (f as Record<string, unknown>).content !== "string") return "each file needs a path and content";
      if (deletes.some((d) => !str(d, 512))) return "each delete is a path";
      return { repository: s.repository, branch: a.branch, message: a.message, ...(files.length && { files }), ...(deletes.length && { deletes }) };
    },
    summary: (a) => {
      const files = Array.isArray(a.files) ? a.files.map((f) => String((f as Record<string, unknown>).path)) : [];
      const deletes = Array.isArray(a.deletes) ? a.deletes.map((d) => `-${String(d)}`) : [];
      return `commit to ${String(a.branch)}: ${[...files, ...deletes].join(", ").slice(0, 160)}`;
    },
  },
  {
    name: "open_pull_request",
    description: "Open a pull request from a branch you committed to, into the default branch unless base is given.",
    parameters: {
      type: "object",
      properties: {
        head: { type: "string", description: "Branch with the changes" },
        base: { type: "string", description: "Branch to merge into; omit for the default branch" },
        title: { type: "string", description: "Pull request title" },
        body: { type: "string", description: "What changed and why" },
      },
      required: ["head", "title", "body"],
    },
    method: "github.pr.Create",
    params: (a, s) => {
      if (!only(a, ["head", "base", "title", "body"]) || !str(a.head, 255) || !a.head || (a.base !== undefined && !str(a.base, 255)) || !str(a.title, 256) || !a.title.trim() || !str(a.body, 16_384))
        return "head, title (1–256 characters), body and an optional base";
      return { repository: s.repository, head: a.head, ...(a.base ? { base: a.base } : {}), title: a.title, body: a.body };
    },
    summary: (a) => `pull request ${String(a.head)} → ${a.base ? String(a.base) : "default branch"}: “${String(a.title ?? "").slice(0, 60)}”`,
  },
  {
    name: "review_pull_request",
    description: "Review a pull request: COMMENT or REQUEST_CHANGES with a body, or APPROVE. Agents can't approve pull requests opened by agents; a person approves those on GitHub.",
    parameters: {
      type: "object",
      properties: {
        number: { type: "integer", description: "Pull request number" },
        event: { type: "string", enum: ["COMMENT", "REQUEST_CHANGES", "APPROVE"] },
        body: { type: "string", description: "Review text (required unless approving)" },
      },
      required: ["number", "event"],
    },
    method: "github.pr.Review",
    params: (a, s) => {
      const events = ["COMMENT", "REQUEST_CHANGES", "APPROVE"];
      if (!only(a, ["number", "event", "body"]) || !int(a.number) || typeof a.event !== "string" || !events.includes(a.event) || (a.body !== undefined && !str(a.body, 16_384))) return "number, event (COMMENT, REQUEST_CHANGES or APPROVE) and body";
      if (a.event !== "APPROVE" && !(typeof a.body === "string" && a.body.trim())) return "a body is required unless approving";
      return { repository: s.repository, number: a.number, event: a.event, ...(a.body ? { body: a.body } : {}) };
    },
    summary: (a) => `${String(a.event ?? "").toLowerCase().replace("_", " ")} review on #${String(a.number)}`,
  },
);

export const toolByName = (name: string) => GITHUB_TOOLS.find((t) => t.name === name);

/** Helpers shared by tools added later. */
export const toolArgs = { str, int, only };

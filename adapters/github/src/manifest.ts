// The signed surface of the adapter: resolved schemas and display templates (docs/adapters.md §2, §6).
// `github.merge_pull_request` v2 and `github.dispatch_workflow` v3 must stay byte-identical to the builtin registry in
// @signeto/protocol.
// Review links (protocol.md §3.5) are built on the approver's device from the signed args, only to github.com.
import type { AdapterManifest, ToolSpec } from "@signeto/adapter-sdk";
import { enm, int, obj, str, stringMap } from "./schema.js";

export const REPO_PATTERN = "^[a-z0-9][a-z0-9._-]*/[a-z0-9._-]+$";
export const REPO_INPUT_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$";
export const SHA_PATTERN = "^[0-9a-f]{40}$";
export const WORKFLOW_PATTERN = "^[A-Za-z0-9._-]+$";
export const REF_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._/-]*$";

/** The only host the review links may point to (protocol.md §3.5). */
export const GITHUB_WEB_HOST = "github.com";
const LINK_HOSTS = [GITHUB_WEB_HOST];

export const MERGE_METHODS = ["merge", "squash", "rebase"] as const;
export type MergeMethod = (typeof MERGE_METHODS)[number];

export const mergePullRequest: ToolSpec = {
  name: "merge_pull_request",
  description: "Merge an open pull request. The approver signs the head SHA; GitHub refuses the merge if the branch moved afterwards.",
  effect: "write",
  classification: "internal",
  input: obj(
    {
      repo: str(REPO_INPUT_PATTERN, 140),
      pr: int(1),
      method: enm(...MERGE_METHODS),
    },
    ["repo", "pr"],
  ),
  resolved: obj(
    {
      repo: str(REPO_PATTERN, 140),
      pr: int(1),
      base: str(REF_PATTERN, 255),
      head_sha: str(SHA_PATTERN, 40),
      method: enm(...MERGE_METHODS),
    },
    ["repo", "pr", "base", "head_sha", "method"],
  ),
  template: {
    id: "github.merge_pull_request",
    version: 2,
    text: "Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}",
    // True because execute merges with `sha: head_sha`: GitHub refuses the merge if the head moved.
    note: "Approving commit {head_sha:short}. If the PR changes, this approval will not merge it.",
    links: [
      { label: "View pull request", url: "https://github.com/{repo:path}/pull/{pr}" },
      { label: "Files changed", url: "https://github.com/{repo:path}/pull/{pr}/files" },
      { label: "Code at approved commit", url: "https://github.com/{repo:path}/tree/{head_sha}" },
    ],
    link_hosts: LINK_HOSTS,
  },
};

export const dispatchWorkflow: ToolSpec = {
  name: "dispatch_workflow",
  description: "Trigger a workflow_dispatch run of a workflow file on a branch or tag. The approver signs the commit the ref pointed at.",
  effect: "write",
  classification: "internal",
  input: obj(
    {
      repo: str(REPO_INPUT_PATTERN, 140),
      workflow: str(WORKFLOW_PATTERN, 255),
      ref: str(REF_PATTERN, 255),
      inputs: stringMap(),
    },
    ["repo", "workflow", "ref"],
  ),
  resolved: obj(
    {
      repo: str(REPO_PATTERN, 140),
      workflow: str(WORKFLOW_PATTERN, 255),
      ref: str(REF_PATTERN, 255),
      ref_sha: str(SHA_PATTERN, 40),
      inputs: stringMap(),
    },
    ["repo", "workflow", "ref", "ref_sha", "inputs"],
  ),
  template: {
    id: "github.dispatch_workflow",
    // v3 (SIG-92 N9): the inputs are in the sentence (v2 elided them). Shown as their JCS text, `{}` when none.
    version: 3,
    text: "Run {workflow} on {ref} ({ref_sha}) in {repo} with inputs {inputs}",
    // `workflow` is resolved to the file name under .github/workflows/ (resolveDispatch).
    links: [
      { label: "Workflow file at approved commit", url: "https://github.com/{repo:path}/blob/{ref_sha}/.github/workflows/{workflow}" },
      { label: "Actions", url: "https://github.com/{repo:path}/actions" },
    ],
    link_hosts: LINK_HOSTS,
  },
};

export const readPullRequest: ToolSpec = {
  name: "read_pull_request",
  description: "Read a pull request's metadata (title, state, head, base, mergeability).",
  effect: "read",
  classification: "public",
  input: obj({ repo: str(REPO_INPUT_PATTERN, 140), pr: int(1) }, ["repo", "pr"]),
  resolved: obj({ repo: str(REPO_PATTERN, 140), pr: int(1) }, ["repo", "pr"]),
  template: {
    id: "github.read_pull_request",
    version: 2,
    text: "Read PR #{pr} on {repo}",
    links: [{ label: "View pull request", url: "https://github.com/{repo:path}/pull/{pr}" }],
    link_hosts: LINK_HOSTS,
  },
};

export const GITHUB_API_HOST = "api.github.com";

export const manifest: AdapterManifest = {
  name: "github",
  version: "0.2.0",
  mode: "mint",
  egress: [GITHUB_API_HOST],
  secrets: [
    { name: "app_id", description: "GitHub App id (numeric, from the App settings page)." },
    { name: "private_key", description: "GitHub App private key, PEM (PKCS#1 or PKCS#8). Used only to sign a short-lived App JWT." },
  ],
  tools: [mergePullRequest, dispatchWorkflow, readPullRequest],
};

/** Optional secret: fixes the installation to mint from. When absent the adapter looks it up per repository with the App JWT. */
export const OPTIONAL_SECRET_INSTALLATION_ID = "installation_id";

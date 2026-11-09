# @signeto/adapter-github

Signeto adapter for GitHub, **mint mode** (docs/adapters.md §3.2, SPEC.md §6.1). Every approved action gets its own
GitHub App installation access token, scoped to the one repository and the permissions that one call needs, valid for
at most an hour, and revoked as soon as `execute` returns. The gateway never holds a GitHub write credential at rest.

## Tools

| Tool | Effect | Agent input | Resolved (signed) args | Headline |
|---|---|---|---|---|
| `github.merge_pull_request` | write | `{repo, pr, method?}` | `{repo, pr, base, head_sha, method}` | `Merge PR #{pr} into {base} on {repo} ({method}) at {head_sha}` |
| `github.dispatch_workflow` | write | `{repo, workflow, ref, inputs?}` | `{repo, workflow, ref, ref_sha, inputs}` | `Run {workflow} on {ref} ({ref_sha}) in {repo} with inputs {inputs}` |
| `github.read_pull_request` | read | `{repo, pr}` | `{repo, pr}` | `Read PR #{pr} on {repo}` |

What `resolve` pins:

- **merge**: looks the PR up with the read-only client, refuses anything that is not open (closed, merged, draft, missing,
  or living in a different repository than the agent named), and signs the **head SHA** and base branch. `method`
  defaults to `squash`. `execute` sends `sha: head_sha` to GitHub's merge endpoint, so GitHub itself refuses with
  `409` if the branch moved after the approver signed; the adapter reports that (and `405`, no longer mergeable) as
  `precondition_failed`. The merge endpoint takes no base, so immediately before the merge `execute` re-reads the PR
  and throws `precondition_failed`, merging nothing and posting no check run, unless `base.ref`, `base.repo.full_name`
  and `head.sha` are still the signed `base`, `repo` and `head_sha` (a PR retargeted from `dev` to `main` after
  approval is refused). When the check run is posted the PR is read again after it, so the last read is the request
  right before the merge.
- **dispatch**: confirms the workflow exists and is active, normalises a numeric workflow id to its file name
  (`deploy.yml`), and signs the **commit SHA** the ref points at. `workflow_dispatch` takes no SHA, so `execute`
  re-reads the ref with the minted token and throws `precondition_failed` without dispatching if it moved, then reads
  it again right after dispatching (see Races).
- **read**: confirms the PR exists; signs only `{repo, pr}`.

### Races

GitHub cannot enforce every signed value, so two small windows remain:

- **merge base**: between the PR re-read and the merge request (one round trip), a retarget is not detectable. GitHub's
  merge endpoint accepts `sha` but no base precondition.
- **dispatch ref**: `workflow_dispatch` resolves the branch or tag when GitHub processes the request. `execute` checks
  the ref is at `ref_sha` as the last request before the dispatch and re-reads it as the first request after. If it
  moved in between, it lists this workflow's `workflow_dispatch` runs on that ref created since the dispatch, cancels
  every one whose `head_sha` is not `ref_sha` (a concurrent dispatch by someone else on the new commit is cancelled
  too: the safe side), and throws `precondition_failed` naming the cancelled runs. It succeeds only if the one run
  found is on `ref_sha`. What remains: the run can execute steps for the seconds before the cancel lands; GitHub may
  not have created the run yet when it is listed (then the action fails and the error says to check Actions; nothing
  is cancelled); a ref moved away and back between the two reads is not seen. A workflow that must never run an
  unapproved commit should also check `github.sha` itself (for example against a protected tag).

Repository names are lower-cased and merge methods normalised, so two spellings of the same action produce the same
canonical bytes (idempotency, SPEC §5).

### Card note and review links (templates v2)

The merge and read templates are version 2, `github.dispatch_workflow` is version 3: version 2 added review links the
approver's device builds from the signed args, only to `github.com` (protocol.md §3.5), and a note on the merge
template. Version 1 of `github.merge_pull_request` stays in the bundled registry for older gateways. Dispatch v3
(SIG-92 N9) puts the workflow `inputs` in the sentence, as their JCS text (`{}` when there are none); v2 elided them,
so an approver saw them only in the argument rows. Dispatch v3 is bundled in `@signeto/protocol` (v2 never was), so
approvers built against this version (CLI, web approver, iOS build 8+) render it without a pin and nobody has to
re-pair. A gateway does not pin bundled templates at pairing, so an approver built before it (iOS build 7, an older
CLI) cannot verify v3 even after re-pairing: it shows dispatch requests from an upgraded gateway as "unverified
template", with the raw bytes and still approvable, until it is updated. The read template is still pinned at
pairing (§5.4).

| Tool | Note | Links |
|---|---|---|
| `merge_pull_request` | `Approving commit {head_sha:short}. If the PR changes, this approval will not merge it.` | View pull request `https://github.com/{repo:path}/pull/{pr}`, Files changed `…/pull/{pr}/files`, Code at approved commit `…/tree/{head_sha}` |
| `dispatch_workflow` | none | Workflow file at approved commit `https://github.com/{repo:path}/blob/{ref_sha}/.github/workflows/{workflow}`, Actions `https://github.com/{repo:path}/actions` |
| `read_pull_request` | none | View pull request `https://github.com/{repo:path}/pull/{pr}` |

The note is true because `execute` merges with `sha: head_sha`. The links show the pages as they are when opened,
which can differ from what was signed; the approval is bound to the signed SHA.

## Secrets

Configure these in the gateway credential store for adapter `github`:

| Secret | Required | Purpose |
|---|---|---|
| `app_id` | yes | The GitHub App's numeric id. |
| `private_key` | yes | The App's private key (PEM, as downloaded from GitHub). Used only to sign a ≤10 minute RS256 JWT in memory with `node:crypto`. |
| `installation_id` | no | Pin the installation to mint from. When absent, the adapter resolves it per repository with `GET /repos/{owner}/{repo}/installation`. |

There is deliberately no personal access token secret. If minting fails for any reason (App not installed on the
repository, GitHub down, malformed or over-long token) the action fails closed with `credential_failed`; the adapter
never falls back to a stored long-lived credential.

### Read-only client for `resolve`

`resolve` only receives the gateway's read-only upstream client. For this adapter that is a `GithubReadOnlyClient`
(a `get(path)` over `https://api.github.com`, no method parameter, so it cannot write). Two constructors:

- `createAppReadOnlyClient({ appId, privateKey, installationId? })` uses the same App secrets as `mint`, so no extra
  credential is stored. It serves only `GET /repos/{owner}/{repo}/...` (anything else is refused), and for each
  repository mints an installation token with `contents:read`, `pull_requests:read`, `actions:read` (GitHub adds
  `metadata:read`) scoped to `repositories: [repo]`. It never requests a write level, refuses a grant broader than
  that, and caches each token until about five minutes before its `expires_at`. Failures fail `resolve` closed.
- `createReadOnlyClient({ token })` takes a read-only credential you already have: a fine-grained PAT limited to the
  same three read permissions, or an installation token minted out of band.

`signeto serve` picks, first match wins: `SIGNETO_GITHUB_READ_TOKEN`; the `github/read_token` secret if it looks like
a GitHub token (`github_pat_`, `ghp_`, `ghs_`, `gho_`; anything else is ignored with a warning); the App
(`app_id` + `private_key`). With none, github tools fail closed at `resolve`.

## Creating the GitHub App

1. GitHub → *Settings* → *Developer settings* → *GitHub Apps* → **New GitHub App** (an organisation-owned App is
   recommended so it survives staff changes).
2. Name it (e.g. `signeto-gateway`), set any homepage URL, **uncheck Webhook → Active** (no webhook needed).
3. *Repository permissions* — the minimum set the adapter can mint from:

   | Permission | Level | Needed by |
   |---|---|---|
   | Contents | Read and write | merge (writes the merge commit); dispatch needs only read for the ref check |
   | Pull requests | Read and write | merge; read tool needs only read |
   | Actions | Read and write | dispatch |
   | Checks | Read and write | optional: the "Signeto" check run on approved merges (see below) |
   | Metadata | Read-only | implied by GitHub for every App |

   Leave every other permission at *No access*. Organisation and account permissions stay empty.
4. *Where can this GitHub App be installed?* → **Only on this account**.
5. Create the App, note the **App ID** (`app_id`), then *Private keys* → **Generate a private key** and store the
   downloaded `.pem` as `private_key`.
6. **Install App** on the organisation, choosing *Only select repositories* and listing exactly the repositories the
   agent may act on. Optionally note the installation id from the URL (`.../installations/<id>`) as `installation_id`.
7. If branch protection requires status checks or reviews, the App's merge is subject to them like any other actor.
   Repository rulesets can additionally bypass-list the App for nothing but merging.

## Mint scope

Each `mint` call builds a fresh App JWT, then `POST /app/installations/{id}/access_tokens` with:

| Tool | `repositories` | `permissions` |
|---|---|---|
| `merge_pull_request` | `[<repo name>]` | `{ contents: "write", pull_requests: "write" }`, plus `checks: "write"` when the installation has accepted it |
| `dispatch_workflow` | `[<repo name>]` | `{ actions: "write", contents: "read" }` |
| `read_pull_request` | `[<repo name>]` | `{ pull_requests: "read" }` |

The adapter refuses the token (`credential_failed`) when GitHub's response lacks a usable `expires_at`, is valid for
more than one hour, or reports any permission or repository beyond what was requested. The credential's `scope` string
written to the ledger looks like:

```
github installation token: repo=acme/api contents:write pull_requests:write installation=99 expires=2026-11-06T13:00:00.000Z
```

## "Signeto" check run

When the installation has accepted **Checks: write**, `mint` adds `checks: "write"` to the merge token (it reads the
installation's permissions first; without the permission the merge works exactly as before). `execute` then posts a
completed, successful check run named `Signeto` on the approved head commit, just before the merge:

- title `Approved by <approver> on <device>`; the summary lists approver, device, `signed_at`, the approved commit,
  the action id and the receipt SHA-256, and how to find the receipt in the ledger;
- `external_id` is the action id; the check run id is added to the evidence as `check_run_id`;
- after the merge, the same check goes on the commit that landed on the base branch (the squash or merge commit),
  so the branch's commit list shows a green check on every commit that came through an approval and none on anything
  that did not; its id is `merge_check_run_id`. It has its own 5 second budget, is skipped when the action deadline is
  less than 2 seconds away, and any failure is recorded as `null`: a merge that happened is never reported as failed;
- best effort: a refused or failed check run is logged and recorded as `check_run_id: null`, and the approved merge
  still goes ahead (the approval is already in the ledger). The adapter learns who approved from
  `ExecuteContext.approval`, which the gateway fills from the verified receipt; tier 1 actions have none and get no check.

Apps created with `signeto setup github` ask for the permission. For an older App: *App settings → Permissions →
Repository permissions → Checks: Read and write → Save*, then accept the new permission on the installation
(*Organization settings → GitHub Apps → Configure → Review request*).

`revoke()` calls `DELETE /installation/token` after `execute`, success or failure (best effort; a failed revoke is
logged and the token expires within the hour anyway).

## Egress

`api.github.com` only. `execute` uses the gateway's egress-restricted `ctx.fetch`. `mint` and `revoke` use the fetch
injected into `createGithubAdapter({ fetch })` (the gateway's `CredentialContext` carries none), defaulting to global
fetch; pass the gateway's restricted fetch there in production.

## Usage

```ts
import { createAppReadOnlyClient, createGithubAdapter, manifest } from "@signeto/adapter-github";

const adapter = createGithubAdapter({ fetch: restrictedFetch });
const readOnly = createAppReadOnlyClient({ appId, privateKey: () => store.get("github").private_key, fetch: restrictedFetch });
// gateway deps (create the client once: it caches one read token per repository):
//   upstreamReadOnly: () => readOnly
//   secrets: () => ({ app_id, private_key, installation_id? })
```

## Development

```
pnpm --filter @signeto/adapter-github typecheck build test
```

Tests run offline against a routed mock fetch: manifest validation, resolve determinism/normalisation, JWT
verification against a test public key, mint scope and fail-closed paths, the App read-only client (read-only scope,
per-repository cache and refresh, path confinement, broader grants refused), execute preconditions (`sha`, 405/409),
revoke, and `(agentArgs, upstreamState) → resolved args → rendered template` fixtures rendered with
`renderTemplate` from `@signeto/protocol`.

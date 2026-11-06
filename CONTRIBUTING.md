# Contributing

Issues and pull requests are welcome, especially new adapters, conformance vectors and integration guides for other agents.

1. Open an issue first for anything larger than a small fix. Protocol changes need agreement before code, because every implementation (gateway, iOS, web) must change in step.
2. `pnpm install && pnpm build && pnpm test` must pass. New protocol behaviour needs a vector under `packages/protocol/vectors/`.
3. Add a changeset (`pnpm changeset`) for anything that changes a published package.
4. One concern per pull request.

By contributing you agree your contribution is licensed under Apache-2.0 (code) or CC-BY-4.0 (docs), matching the file you change.

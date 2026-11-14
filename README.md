<p align="center"><img src="docs/assets/mark.svg" width="72" alt="Signeto"></p>

# Signeto

**Your agent can't ship to prod without your fingerprint.**

Signeto is an approval gateway for AI agents. Before an agent takes a sensitive action (merge to main, run a migration, move money), a person signs the *exact* action on their phone or laptop with a hardware-backed key. The gateway verifies that signature, mints a credential scoped to that one action, runs it, and writes a hash-chained receipt. No signature, no action. The agent never holds the credential.

This repository is the **integration toolkit**: the open protocol, the libraries you build against, a reference adapter, and the guide for wiring Signeto into your agents. The Signeto service itself (gateway, relay, portal, approver apps) is run by Signeto; see [signeto.dev](https://signeto.dev).

> **Status: early access.** The hosted relay, the iPhone app and the [`signeto`](https://www.npmjs.com/package/signeto) CLI are live. The packages in this repository are stable enough to build against but not yet on npm; version numbers are `0.x` until then.

## Install Signeto

To put Signeto in front of your own agents, follow the guide for your machine on signeto.dev. Each guide has a video of every step.

| Machine | Guide |
|---|---|
| macOS | [signeto.dev/docs/install-macos](https://signeto.dev/docs/install-macos/) |
| Linux | [signeto.dev/docs/install-linux](https://signeto.dev/docs/install-linux/) |
| Windows | [signeto.dev/docs/install-windows](https://signeto.dev/docs/install-windows/) |

If something fails, `signeto doctor` names the problem; [troubleshooting](https://signeto.dev/docs/troubleshooting/) lists each error and its fix.

## What's here

| Path | Package | What it's for |
|---|---|---|
| [`packages/protocol`](packages/protocol) | `@signeto/protocol` | Canonical action bytes (RFC 8785), display templates, receipts, signature verification for ES256, Ed25519 and WebAuthn. Ships the conformance vectors every implementation must pass. |
| [`packages/adapter-sdk`](packages/adapter-sdk) | `@signeto/adapter-sdk` | The adapter interface: manifest, `resolve` / `mint` / `custody` / `execute` hooks, `AdapterError`, manifest validation. Use it to bring a new upstream system under Signeto. |
| [`adapters/github`](adapters/github) | `@signeto/adapter-github` | Reference adapter: GitHub App installation tokens minted per action (merge a PR, dispatch a workflow). Shows the mint pattern end to end. |
| [`ios`](ios) | SignetoSign (Swift) | The approver-device side of the protocol for iOS and macOS: verify requests, render templates, sign receipts, pair. The Signeto iPhone app is built on it. |
| [`android`](android) | signeto-sign (Kotlin) | The same library for Android and the JVM, a port of SignetoSign with the same tests. The Signeto Android app is built on it. |
| [`docs/guide`](docs/guide) | | Integration guide: how agents connect, what they see, how to read results. |
| [`docs/protocol.md`](docs/protocol.md) | | The normative protocol. |
| [`docs/receipts.md`](docs/receipts.md) | | Verify a Signeto receipt yourself, with no Signeto service in the loop. |
| [`docs/security.md`](docs/security.md) | | What Signeto guarantees in each deployment mode, and what it doesn't. |
| [`examples`](examples) | | Agent configuration snippets. |

## Develop

Node 22.13 or newer and pnpm 10.

```sh
pnpm install
pnpm build
pnpm test
```

## License

Code: Apache-2.0 (see [LICENSE](LICENSE)). Protocol specification and docs: CC-BY-4.0.
Security issues: see [SECURITY.md](SECURITY.md).

# @signeto/adapter-sdk

The interface an adapter implements to bring an upstream system under Signeto: its manifest (tools, input and resolved schemas, display templates, credential mode, egress, secrets) and the `resolve`, `mint` / `custody` and `execute` hooks. The gateway does everything else: policy, the approval on a phone, the ledger, retries.

```sh
npm install @signeto/adapter-sdk
```

```ts
import { AdapterError, validateAdapter, type Adapter } from "@signeto/adapter-sdk";
```

- `Adapter`, `AdapterManifest`, `ToolSpec`, `DisplayTemplate`: the types an adapter implements; `ExecuteContext.approval` says who approved.
- `AdapterError`: throw it with a stable code (`resolve_failed`, `upstream_rejected`, `precondition_failed`, …); the agent sees the code, never a stack.
- `validateAdapter`: the manifest checks the gateway runs at load (schemas, templates, mode hooks).

Guide with a worked example: [Write an adapter](https://github.com/signeto/signeto/blob/main/docs/guide/README.md#write-an-adapter). Reference adapter: [`@signeto/adapter-github`](https://github.com/signeto/signeto/tree/main/adapters/github).

## License

Apache-2.0.

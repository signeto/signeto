---
"@signeto/adapter-github": patch
---

A failed request to GitHub is reported by its error class only, never by fetch's own message: fetch rejects a header value with a line break with an error that quotes the whole value, which would have put a token into the error the agent and the ledger see.

---
"@signeto/adapter-github": patch
---

App JWTs expire 10 minutes after their backdated `iat` (9 minutes after now) instead of exactly 10 minutes after now. A machine whose clock ran even a second ahead of GitHub's got `401 'Expiration time' claim ('exp') is too far in the future` when minting an installation token or reading an App's installation.

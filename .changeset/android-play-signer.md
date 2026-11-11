---
"@signeto/protocol": minor
---

`@signeto/protocol/androidkey`: `SIGNETO_ANDROID_SIGNERS` lists the Signeto Android app's Play App Signing certificate, so a statement from the app installed from Google Play verifies as `production` by default. `SIGNETO_ANDROID_PACKAGES` (the default accepted packages) adds the app's development flavour `dev.signeto.approver.dev`, which vouches only through a listed development signer.

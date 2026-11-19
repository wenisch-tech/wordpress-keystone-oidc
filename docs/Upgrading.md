---
title: Upgrading
---

## Client types and token endpoint authentication

Earlier versions only checked the client secret when one was sent. A request that omitted it was accepted for any client, so an authorization code that leaked could be redeemed without the secret unless PKCE was used. From this release the token endpoint always authenticates confidential clients, and every client has a **type**.

### What changes on upgrade

- The database schema is upgraded automatically on the next request. No re-activation is needed.
- **All existing clients become confidential.** Clients that already send their secret keep working unchanged.
- Clients that relied on PKCE **without** a secret (SPAs, mobile apps) will now get `401 invalid_client` until you open them under **OIDC Provider → Clients** and set the type to **Public**.
- Public clients must use `S256` PKCE. The authorize endpoint rejects anything else.

### Other behavior changes

- HTTP Basic credentials are now URL-decoded as RFC 6749 requires. Secrets are hex strings, so this changes nothing in practice.
- Unknown `code_challenge_method` values and malformed challenges or verifiers are rejected instead of being treated as `plain`.
- Discovery now lists `none` among the token endpoint authentication methods.

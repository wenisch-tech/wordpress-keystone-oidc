---
title: Security
---

## Client authentication

Confidential clients must authenticate at the token endpoint on every request, and public clients must use S256 PKCE. See [Client types](Client-Types.md). In earlier versions a missing secret was accepted for any client; see [Upgrading](Upgrading.md).

## Secret storage

Client secrets are never stored in plaintext. When a secret is created or reset the plugin:

1. generates a cryptographically random 64-character hex string,
2. hashes it with WordPress's `wp_hash_password()`,
3. stores only the hash,
4. shows the plaintext once through a 5-minute transient.

After that the plaintext can't be recovered, only reset.

## Codes and tokens

- Authorization codes are single use and expire after 10 minutes. The client ID and redirect URI must match the authorization request.
- Redirect URIs are matched exactly. Private-use schemes for native apps are accepted for public clients only, must be reverse-domain names and are always protected by mandatory PKCE, see [Native apps](Client-Types.md#native-apps-private-use-uri-schemes).
- The authorize endpoint only redirects an error back to the client after the `redirect_uri` has been verified against the registered list.
- PKCE values are validated against RFC 7636 (43-128 unreserved characters). Unknown challenge methods are rejected.
- Refresh tokens rotate on every use.
- A user's tokens are revoked automatically when the user is deleted, resets their password or changes it. Refresh tokens of deleted users are always rejected.
- Sites can add their own rules (for example blocking banned users) with the [`keystone_oidc_authorize_user`](Extending.md#keystone_oidc_authorize_user) and [`keystone_oidc_refresh_allowed`](Extending.md#keystone_oidc_refresh_allowed) filters.
- Rotating the signing keys invalidates every issued JWT at once.

## Reporting a vulnerability

Please open a private security advisory on the [GitHub repository](https://github.com/wenisch-tech/wordpress-keystone-oidc/security/advisories/new) rather than a public issue.

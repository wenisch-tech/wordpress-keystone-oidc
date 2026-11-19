---
title: Troubleshooting
---

## Endpoints return 404

- Enable pretty permalinks under *Settings → Permalinks*.
- Click **Save Changes** on that page once to flush the rewrite rules.

## "Invalid redirect_uri"

The redirect URI must match a registered URI exactly, including scheme, host, path and trailing slash. Check `http` against `https`.

## `invalid_client` at the token endpoint

- The client is **confidential** and no valid secret was sent. Send it with HTTP Basic auth or as `client_secret` in the body.
- The secret was reset. Use the new one, or reset it again from the client page.
- The application is a SPA or mobile app with no secret. Set the client type to **Public** and use PKCE.

## `invalid_request` at the authorize endpoint

- A public client must send `code_challenge` and `code_challenge_method=S256`.
- `code_challenge_method` must be `S256` or `plain`, and the challenge must be 43-128 unreserved characters.

## `invalid_grant` at the token endpoint

- The code was already used or has expired (10 minutes).
- `redirect_uri` differs from the authorize request.
- `code_verifier` is missing or doesn't match the challenge.

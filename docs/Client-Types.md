---
title: Client types
---

Every client is either **confidential** or **public**. The type decides how the client proves its identity at the token endpoint.

| | Confidential | Public |
|---|---|---|
| Typical app | Server-side web app, backend service | Single-page app, mobile or desktop app |
| Can keep a secret | Yes | No |
| Client secret | Generated, shown once, stored hashed | None |
| Token endpoint authentication | **Required** (Basic or POST body) | None (`token_endpoint_auth_method=none`) |
| PKCE | Optional, verified if used | **Required**, `S256` only |

## Confidential clients

The token endpoint always requires the client secret, for both the `authorization_code` and `refresh_token` grants. A request without a valid secret is rejected with `401 invalid_client` and a `WWW-Authenticate: Basic` header. An authorization code that leaks (through logs, a referrer or a misconfigured redirect) is useless without the secret.

Send the credentials either way:

- HTTP Basic: `Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))`
- POST body: `client_id` and `client_secret`

If both are present, the `client_id` values must match.

## Public clients

A public client has nothing secret to present, so the authorization request itself must be bound to the client with PKCE:

- `/oauth/authorize` rejects requests that lack `code_challenge`, or that use a method other than `S256`, with `invalid_request`.
- `/oauth/token` requires the matching `code_verifier`. A code that was issued without a challenge is refused with `invalid_grant`.

Refresh tokens are rotated on every use, which limits the damage if one leaks.

## Choosing a type

Use **confidential** whenever the application runs on a server you control. Use **public** only when the code runs on the user's device and can't hide a secret. If you are unsure, pick confidential.

Change the type at any time under **OIDC Provider → Clients → (client)**. Switching to public does not delete the stored secret hash, but it is no longer used.

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

## Native apps (private-use URI schemes)

Android and iOS apps usually can't receive a redirect on a web URL. RFC 8252 §7.1 therefore lets them register a **private-use URI scheme** that the operating system routes back to the app. AppAuth uses this by default.

Public clients may register redirect URIs such as:

```
com.example.app:/oauth2redirect
com.example.app://oauth2redirect
```

Rules (checked when you save the client):

- Only **public** clients may use them. A confidential client with such a URI is rejected.
- The scheme must be a **reverse domain name**, so it contains a dot (`com.example.app`). Schemes like `myapp` are rejected, as are `javascript`, `data`, `vbscript`, `file`, `blob` and `about`.
- The scheme must be followed by `/`. Whitespace, control characters and `#fragments` are rejected.
- As for every redirect URI, the match is **exact** at authorization and at the token endpoint.

Use the domain you control, reversed, as the scheme. This is the recommendation of the RFC and makes accidental collisions unlikely.

:::warning
Another app on the same device can register the same scheme and receive the authorization code. This is why public clients must use PKCE `S256`: a stolen code is useless without the `code_verifier`, which never leaves your app. Where the platform supports it, **claimed `https` redirects** (Android App Links, iOS Universal Links, RFC 8252 §7.2) are more secure, because the OS verifies that the app owns the domain. They work with Keystone without any special setting, since they are ordinary `https` redirect URIs.
:::

AppAuth for Android example:

```kotlin
val config = AuthorizationServiceConfiguration(
    Uri.parse("https://example.com/wenisch-tech/keystone-oidc/oauth/authorize"),
    Uri.parse("https://example.com/wenisch-tech/keystone-oidc/oauth/token"))
val request = AuthorizationRequest.Builder(
        config, "<client_id>", ResponseTypeValues.CODE,
        Uri.parse("com.example.app:/oauth2redirect"))
    .setScope("openid profile email")
    .build() // AppAuth adds PKCE (S256) automatically
```

## Choosing a type

Use **confidential** whenever the application runs on a server you control. Use **public** only when the code runs on the user's device and can't hide a secret. If you are unsure, pick confidential.

Change the type at any time under **OIDC Provider → Clients → (client)**. Switching to public does not delete the stored secret hash, but it is no longer used.

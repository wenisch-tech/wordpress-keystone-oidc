---
slug: /
title: Keystone OIDC
sidebar_label: Overview
---

Keystone OIDC is a WordPress plugin that turns your site into a fully featured **OpenID Connect (OIDC) identity provider**. Dashboards, CLIs, mobile apps and any other OIDC-aware tool can sign users in against your existing WordPress user database. No external identity provider is needed.

## Features

- **Authorization Code flow** (RFC 6749 / OpenID Connect Core 1.0).
- **Confidential and public clients.** Confidential clients authenticate with a secret; public clients (SPAs, mobile apps) use PKCE. See [Client types](Client-Types.md).
- **PKCE** with `S256` and `plain` (RFC 7636).
- **RS256 JWT** access tokens and ID tokens, with a JWKS endpoint for offline verification.
- **Refresh tokens** with single-use rotation.
- **OIDC Discovery** for zero-config clients.
- **Multi-client management** from the WordPress admin.
- **Extension hooks** for sign-in rules, custom claims, token lifetimes and token revocation. See [Extending with hooks](Extending.md).
- **Roles scope** to release WordPress roles as an OIDC claim.
- **Consent screen**, **signing-key rotation** and automatic cleanup of expired codes and tokens.

## Where to go next

| I want to… | Read |
|---|---|
| Install the plugin | [Installation](Installation.md) |
| Connect my first application | [Quick start](Quick-Start.md) |
| Manage clients in the admin | [Admin guide](Admin-Guide.md) |
| Understand the flow and token handling | [How it works](How-It-Works.md) |
| Choose between public and confidential | [Client types](Client-Types.md) |
| Customize sign-in rules, claims or lifetimes with hooks | [Extending with hooks](Extending.md) |
| Look up an endpoint or parameter | [Endpoint reference](Endpoint-Reference.md) |
| Upgrade from an earlier version | [Upgrading](Upgrading.md) |

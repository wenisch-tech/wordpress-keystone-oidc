---
title: Quick start
---

## 1. Create a client

Go to **OIDC Provider → Add Client** and fill in:

- **Application Name**: a friendly label shown on the consent screen.
- **Redirect URIs**: the callback URL(s), one per line. They must match exactly.
- **Client Type**: *Confidential* for server-side apps that can keep a secret, *Public* for SPAs and mobile apps. See [Client types](Client-Types.md).
- **Allowed Scopes**: tick `profile`, `email` and/or `roles` as needed.

Click **Create Client**. For a confidential client the **Client ID** and **Client Secret** are shown once, so copy them now. Public clients only have a Client ID.

## 2. Configure your application

Point your OIDC library at the discovery URL:

```text
https://your-site.example.com/wenisch-tech/keystone-oidc/.well-known/openid-configuration
```

Then provide:

- the **Client ID** and, for confidential clients, the **Client Secret**;
- the redirect URI you registered;
- the scopes `openid` plus any of `profile`, `email`, `roles`.

Public clients must also send a PKCE `code_challenge` using `S256`. Most OIDC libraries do this automatically when no client secret is configured.

Your users can now sign in with their WordPress credentials.

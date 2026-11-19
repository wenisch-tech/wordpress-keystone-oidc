---
title: Admin guide
---

## Client list

**OIDC Provider → Clients** lists every client with its name, ID, type, allowed scopes and creation date. The discovery URL is shown at the top. Click a client to edit it.

## Add or edit a client

**Client Credentials** (edit view)
- The **Client ID** with a copy button, and the discovery URL.
- For confidential clients, a **Reset Secret** button. Resetting generates a new secret and invalidates the old one immediately; the new secret is shown once.
- Public clients show *None* instead, because they have no secret.

**Configuration**
- *Application Name*: shown on the consent screen.
- *Redirect URIs*: exact match, one per line, no wildcards. Public clients (native apps) may also use a reverse-domain scheme such as `com.example.app:/oauth2redirect`, see [Native apps](Client-Types.md#native-apps-private-use-uri-schemes). Invalid URIs are rejected when you save.
- *Client Type*: *Confidential* or *Public*. See [Client types](Client-Types.md).
- *Allowed Scopes*: which scopes the client may request. `openid` is always included.

**Danger zone**
- **Delete Client** permanently removes the client and all of its codes and tokens.

## Settings

**OIDC Provider → Settings** shows the issuer URL, all endpoint URLs, the current signing key ID (`kid`) and the plugin version.

**Rotate Signing Keys** generates a new RSA-2048 key pair. All previously issued access and ID tokens become invalid immediately. Use it after a suspected key compromise.

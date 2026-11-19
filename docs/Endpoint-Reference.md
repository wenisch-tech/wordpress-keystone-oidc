---
title: Endpoint reference
---

All paths are relative to the site root.

| Endpoint | Method | Path |
|---|---|---|
| Discovery | GET | `/wenisch-tech/keystone-oidc/.well-known/openid-configuration` |
| Authorization | GET / POST | `/wenisch-tech/keystone-oidc/oauth/authorize` |
| Token | POST | `/wenisch-tech/keystone-oidc/oauth/token` |
| UserInfo | GET | `/wenisch-tech/keystone-oidc/oauth/userinfo` |
| JWKS | GET | `/wenisch-tech/keystone-oidc/oauth/jwks` |

For clients that derive Keycloak-style paths, `/protocol/openid-connect/auth`, `/token`, `/userinfo` and `/certs` are routed to the same handlers. They aren't advertised in discovery; new clients should use the discovery document.

## Discovery

```json
{
  "issuer": "https://example.com/wenisch-tech/keystone-oidc",
  "authorization_endpoint": "https://example.com/wenisch-tech/keystone-oidc/oauth/authorize",
  "token_endpoint": "https://example.com/wenisch-tech/keystone-oidc/oauth/token",
  "userinfo_endpoint": "https://example.com/wenisch-tech/keystone-oidc/oauth/userinfo",
  "jwks_uri": "https://example.com/wenisch-tech/keystone-oidc/oauth/jwks",
  "scopes_supported": ["openid", "profile", "email", "roles"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

## Authorize

| Parameter | Required | Description |
|---|---|---|
| `response_type` | yes | Must be `code` |
| `client_id` | yes | The client's ID |
| `redirect_uri` | yes | Exact match of a registered URI |
| `scope` | yes | Space-separated, must include `openid` |
| `state` | recommended | Echoed back, protects against CSRF |
| `nonce` | recommended | Included in the ID token |
| `code_challenge` | public: yes | Base64url challenge, 43-128 characters |
| `code_challenge_method` | public: `S256` | `S256` or `plain` (confidential clients only) |

## Token

**Client authentication.** Confidential clients must send one of:

- `Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))`
- `client_id` and `client_secret` in the POST body

Public clients send only `client_id`.

**Authorization code grant** (`grant_type=authorization_code`):

| Parameter | Required | Description |
|---|---|---|
| `code` | yes | Code from the authorize endpoint |
| `redirect_uri` | yes | Same value as in the authorize request |
| `client_id` | yes | Not needed when sent through Basic auth |
| `code_verifier` | PKCE | Required when a `code_challenge` was used, and always for public clients |

**Refresh token grant** (`grant_type=refresh_token`): send `refresh_token` and `client_id`. Confidential clients authenticate as above.

**Response:**

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "<JWT>",
  "refresh_token": "<opaque string>",
  "scope": "openid profile email"
}
```

**Errors:**

| Error | Status | Cause |
|---|---|---|
| `invalid_client` | 401 | Unknown client, or a confidential client without valid credentials |
| `invalid_request` | 400 | For example a `client_id` mismatch between header and body |
| `invalid_grant` | 400 | Bad, expired or reused code; redirect URI mismatch; missing or wrong `code_verifier` |
| `unsupported_grant_type` | 400 | Only `authorization_code` and `refresh_token` are supported |

## UserInfo

Send `Authorization: Bearer <access_token>`. The response contains the claims for the granted scopes. See [Scopes and claims](Scopes-And-Claims.md).

## JWKS

Returns the public RSA key in [JWKS format](https://datatracker.ietf.org/doc/html/rfc7517) for verifying RS256 tokens.

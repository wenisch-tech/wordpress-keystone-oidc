---
title: Scopes and claims
---

| Scope | Claims included |
|---|---|
| `openid` | `sub`, `iss`, `aud`, `iat`, `exp`, `jti` |
| `profile` | `name`, `given_name`, `family_name`, `preferred_username` |
| `email` | `email`, `email_verified` |
| `roles` | `roles` (array of WordPress role slugs) |

`sub` is always the WordPress user ID as a string, giving a stable identity. `preferred_username` is the WordPress `user_login`, and `email` is `user_email`.

## Roles

With the `roles` scope the ID token and the UserInfo response contain a flat `roles` array, for example `"roles": ["editor"]`. The scope must be allowed on the client **and** requested by the application. WordPress has no native groups, so no `groups` claim is emitted. Plugins can adjust the released roles with the `keystone_oidc_user_roles` filter, and add custom claims with the claims filters described in [Extending with hooks](Extending.md#claims-filters).

## Example UserInfo response

```json
{
  "sub": "42",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "preferred_username": "jane",
  "email": "jane@example.com",
  "email_verified": true
}
```

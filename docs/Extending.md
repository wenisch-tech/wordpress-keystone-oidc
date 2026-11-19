---
title: Extending with hooks
---

Keystone OIDC exposes WordPress filters and actions so you can adapt sign-in rules, token contents and token lifetimes **without forking the plugin**. Put the code in a [must-use plugin](https://developer.wordpress.org/advanced-administration/plugins/mu-plugins/) (`wp-content/mu-plugins/`) or in your own plugin. Hooks survive plugin updates.

## Hook overview

| Hook | Type | When it runs | Purpose |
|---|---|---|---|
| [`keystone_oidc_authorize_user`](#keystone_oidc_authorize_user) | filter | Authorization request of a logged-in user | Decide whether this user may sign in to this client |
| [`keystone_oidc_refresh_allowed`](#keystone_oidc_refresh_allowed) | filter | Refresh token grant | Re-check the user before new tokens are issued |
| [`keystone_oidc_id_token_claims`](#claims-filters) | filter | ID token creation | Add or change ID token claims |
| [`keystone_oidc_access_token_claims`](#claims-filters) | filter | Access token creation | Add or change access token claims |
| [`keystone_oidc_userinfo_claims`](#claims-filters) | filter | UserInfo request | Add or change the UserInfo response |
| [`keystone_oidc_user_roles`](#keystone_oidc_user_roles) | filter | Building the `roles` claim | Change the released role slugs |
| [`keystone_oidc_auth_code_lifetime`](#token-lifetimes) | filter | Issuing an authorization code | Change its lifetime |
| [`keystone_oidc_access_token_lifetime`](#token-lifetimes) | filter | Issuing tokens | Change the access and ID token lifetime |
| [`keystone_oidc_refresh_token_lifetime`](#token-lifetimes) | filter | Issuing tokens | Change the refresh token lifetime |
| [`keystone_oidc_tokens_revoked`](#keystone_oidc_tokens_revoked) | action | After a user's tokens were revoked | React to revocation (logging, cache purge) |

Plus one public method: [`KEYSTONE_OIDC_Token_Manager::revoke_user_tokens()`](#revoking-tokens).

## `keystone_oidc_authorize_user`

Decides whether the logged-in user may sign in to the client. It runs for every authorization request after the user is authenticated, both when the consent screen is requested and when it is submitted. A rejected user is sent back to the client's redirect URI with `error=access_denied` and never sees the consent screen.

```php
apply_filters( 'keystone_oidc_authorize_user', true, WP_User $user, string $client_id, string $scope );
```

| Parameter | Description |
|---|---|
| `$allowed` | `true` by default |
| `$user` | The logged-in `WP_User` |
| `$client_id` | The OIDC client ID |
| `$scope` | The granted scope string, for example `openid profile email` |

**Return** `true` to allow. Return `false` or a `WP_Error` to deny. The `WP_Error` message becomes the `error_description` sent to the client, so do not put sensitive details in it.

### Example: only approved members may sign in to the mobile app

```php
add_filter( 'keystone_oidc_authorize_user', function ( $allowed, $user, $client_id, $scope ) {
    if ( 'abc123mobileclient' !== $client_id ) {
        return $allowed; // Only restrict this client.
    }
    if ( ! in_array( 'member', (array) $user->roles, true ) ) {
        return new WP_Error( 'not_a_member', 'Your account is not approved yet.' );
    }
    return $allowed;
}, 10, 4 );
```

:::note
This filter only controls **new sign-ins**. Tokens that were already issued stay valid. Pair it with [`keystone_oidc_refresh_allowed`](#keystone_oidc_refresh_allowed) and [token revocation](#revoking-tokens).
:::

## `keystone_oidc_refresh_allowed`

Runs when a client exchanges a refresh token, after the token itself has been validated (known, not revoked, not expired, matching client) and before new tokens are issued. Without it, a banned user would keep receiving new tokens for as long as the app keeps refreshing, because every refresh issues a new refresh token.

```php
apply_filters( 'keystone_oidc_refresh_allowed', true, int $user_id, string $client_id );
```

Return `false` or a `WP_Error` to reject the grant with `400 invalid_grant`. The client must then send the user through a new sign-in.

A refresh token whose user no longer exists is **always** rejected with `invalid_grant`, even if no filter is registered.

```php
add_filter( 'keystone_oidc_refresh_allowed', function ( $allowed, $user_id, $client_id ) {
    $user = get_userdata( $user_id );
    if ( ! $user || ! in_array( 'member', (array) $user->roles, true ) ) {
        return false;
    }
    return $allowed;
}, 10, 3 );
```

## Claims filters

Three filters let you add or change claims. All receive the same arguments:

```php
apply_filters( 'keystone_oidc_id_token_claims',     array $claims, WP_User|false $user, string $client_id, array $scopes );
apply_filters( 'keystone_oidc_access_token_claims', array $claims, WP_User|false $user, string $client_id, array $scopes );
apply_filters( 'keystone_oidc_userinfo_claims',     array $claims, WP_User|false $user, string $client_id, array $scopes );
```

| Parameter | Description |
|---|---|
| `$claims` | The claims about to be signed or returned |
| `$user` | The `WP_User`, or `false` if the user could not be loaded |
| `$client_id` | The client the token is issued for (the token's `aud`) |
| `$scopes` | Array of granted scopes, for example `['openid', 'profile']` |

| Filter | Where the claims end up |
|---|---|
| `keystone_oidc_id_token_claims` | The ID token payload |
| `keystone_oidc_access_token_claims` | The access token JWT payload (visible to resource servers that verify it offline) |
| `keystone_oidc_userinfo_claims` | The JSON response of the UserInfo endpoint |

### Protected claims

To keep tokens valid and verifiable, these claims are restored to their original value after your filter runs, so you can't override them: `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and `nonce`. If a filter returns something that is not an array, the original claims are used.

### Example: add a membership claim

```php
add_filter( 'keystone_oidc_id_token_claims', 'my_membership_claim', 10, 4 );
add_filter( 'keystone_oidc_userinfo_claims', 'my_membership_claim', 10, 4 );

function my_membership_claim( $claims, $user, $client_id, $scopes ) {
    if ( $user && in_array( 'profile', $scopes, true ) ) {
        $claims['membership'] = my_get_membership_group( $user->ID );
    }
    return $claims;
}
```

Hook the ID token and UserInfo filters together if the application reads the claim from either place. Respect the scopes: only release personal data when the matching scope was granted.

:::tip
Keep access token claims small and non-sensitive. Access tokens are sent with every API request, and any holder can read them (a JWT is signed, not encrypted).
:::

## `keystone_oidc_user_roles`

Changes the role slugs released in the `roles` claim (requires the `roles` scope). See [Scopes and claims](Scopes-And-Claims.md#roles).

```php
apply_filters( 'keystone_oidc_user_roles', string[] $roles, WP_User $user );
```

## Token lifetimes

Three filters change how long codes and tokens live. Each receives the default in seconds and the client ID, so you can set different values per client. Return a positive integer; anything else falls back to the default.

| Filter | Default | Applies to |
|---|---|---|
| `keystone_oidc_auth_code_lifetime` | `600` (10 minutes) | Authorization codes |
| `keystone_oidc_access_token_lifetime` | `3600` (1 hour) | Access tokens and ID tokens, and the `expires_in` response value |
| `keystone_oidc_refresh_token_lifetime` | `2592000` (30 days) | Refresh tokens |

```php
// Shorter refresh tokens for everyone.
add_filter( 'keystone_oidc_refresh_token_lifetime', fn() => 7 * DAY_IN_SECONDS );

// 15 minute access tokens for one client only.
add_filter( 'keystone_oidc_access_token_lifetime', function ( $seconds, $client_id ) {
    return 'abc123mobileclient' === $client_id ? 15 * MINUTE_IN_SECONDS : $seconds;
}, 10, 2 );
```

Lifetime changes apply to tokens issued **after** the change. Existing tokens keep their original expiry.

## Revoking tokens

```php
KEYSTONE_OIDC_Token_Manager::revoke_user_tokens( int $user_id, ?string $client_id = null ): int
```

Revokes all access and refresh tokens of a user. Pass a `$client_id` to revoke only that client's tokens. Returns the number of token records revoked.

```php
// Sign the user out of every application.
KEYSTONE_OIDC_Token_Manager::revoke_user_tokens( $user_id );

// Sign the user out of one application only.
KEYSTONE_OIDC_Token_Manager::revoke_user_tokens( $user_id, 'abc123mobileclient' );
```

### Automatic revocation

Keystone revokes all of a user's tokens when:

| Event | WordPress hook used |
|---|---|
| The user is deleted | `delete_user` |
| The user resets their password | `after_password_reset` |
| The password hash changes through `wp_update_user()` (profile page, admin edit) | `profile_update` |

:::note
Code that calls `wp_set_password()` directly does not fire `profile_update`. If your plugin changes passwords that way, call `revoke_user_tokens()` yourself. The same applies to your own ban or suspend logic.
:::

### What revocation affects

- **Refresh tokens:** the next refresh fails with `invalid_grant`.
- **Access tokens:** the UserInfo endpoint rejects them with `401 invalid_token`.
- **Resource servers that only verify the JWT signature offline** can't know about revocation. The token stays valid there until it expires (1 hour by default). Shorten the lifetime with [`keystone_oidc_access_token_lifetime`](#token-lifetimes) if that matters to you.

## `keystone_oidc_tokens_revoked`

Fires after `revoke_user_tokens()` ran, including the automatic cases above.

```php
do_action( 'keystone_oidc_tokens_revoked', int $user_id, ?string $client_id, int $count );
```

| Parameter | Description |
|---|---|
| `$user_id` | The affected user |
| `$client_id` | The client, or `null` when all clients were affected |
| `$count` | Number of token records that were revoked |

```php
add_action( 'keystone_oidc_tokens_revoked', function ( $user_id, $client_id, $count ) {
    error_log( sprintf( 'Revoked %d OIDC tokens for user %d (%s)', $count, $user_id, $client_id ?? 'all clients' ) );
}, 10, 3 );
```

## Complete example: members-only app

A single mu-plugin that restricts an app to members, keeps checking on refresh, cuts access when a member is banned, and adds a claim:

```php
<?php
/**
 * Plugin Name: Keystone OIDC – members only
 */

const MY_APP_CLIENT_ID = 'abc123mobileclient';

function my_is_approved( $user ) {
    return $user && in_array( 'member', (array) $user->roles, true );
}

add_filter( 'keystone_oidc_authorize_user', function ( $allowed, $user, $client_id ) {
    if ( MY_APP_CLIENT_ID === $client_id && ! my_is_approved( $user ) ) {
        return new WP_Error( 'not_approved', 'Account not approved.' );
    }
    return $allowed;
}, 10, 3 );

add_filter( 'keystone_oidc_refresh_allowed', function ( $allowed, $user_id, $client_id ) {
    if ( MY_APP_CLIENT_ID === $client_id && ! my_is_approved( get_userdata( $user_id ) ) ) {
        return false;
    }
    return $allowed;
}, 10, 3 );

add_filter( 'keystone_oidc_id_token_claims', function ( $claims, $user ) {
    if ( $user ) {
        $claims['membership'] = get_user_meta( $user->ID, 'membership_group', true );
    }
    return $claims;
}, 10, 2 );

// When a member loses the role, cut access immediately.
add_action( 'remove_user_role', function ( $user_id, $role ) {
    if ( 'member' === $role ) {
        KEYSTONE_OIDC_Token_Manager::revoke_user_tokens( $user_id, MY_APP_CLIENT_ID );
    }
}, 10, 2 );
```

## Good practice

- **Return the incoming value** when your rule does not apply (`return $allowed;`) so several plugins can use the same filter together.
- **Keep filters fast.** They run on sign-in, on every refresh and, for UserInfo claims, on every UserInfo call. Avoid remote requests.
- **Don't leak internals** in `WP_Error` messages. They reach the client application.
- **Hooks run on trusted code paths only.** They are not a replacement for scope or client settings, which stay enforced by the plugin.
- **Not covered yet:** the redirect URI rules and the client type are not filterable. Custom URI schemes for native apps are tracked separately.

## Troubleshooting hooks

| Symptom | Likely cause |
|---|---|
| A custom claim is missing from the ID token | The filter was registered after the token was issued (for example inside an admin-only action), or it returned a non-array |
| A claim I set (`sub`, `exp`, …) is ignored | It's a [protected claim](#protected-claims) |
| A banned user can still call UserInfo | The access token was not revoked. Call `revoke_user_tokens()` on ban |
| Lifetime change has no effect | It only applies to tokens issued after the change; check the filter is registered early enough (`plugins_loaded` or an mu-plugin) |

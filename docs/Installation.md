---
title: Installation
---

## Requirements

- WordPress 5.6 or later and PHP 7.4 or later.
- The PHP `openssl` extension (used to generate the RSA signing keys).
- **Pretty permalinks** enabled (*Settings → Permalinks*). The OIDC endpoints use rewrite rules.
- HTTPS. OIDC clients and browsers expect a secure issuer URL.

## Option A: upload the ZIP (recommended)

1. Download `keystone-oidc-x.y.z.zip` from the [latest release](https://github.com/wenisch-tech/wordpress-keystone-oidc/releases/latest), or install **Keystone OIDC** from the WordPress.org plugin directory.
2. In WordPress go to **Plugins → Add New → Upload Plugin**, choose the ZIP and click **Install Now**.
3. Click **Activate**.

## Option B: manual copy

Copy the `keystone-oidc/` folder into `wp-content/plugins/` and activate it from the **Plugins** screen.

## What happens on activation

- The database tables for clients, authorization codes and tokens are created.
- An RSA-2048 signing key pair is generated and stored in the options table.
- Rewrite rules are flushed so the OIDC endpoints resolve.

If an endpoint returns 404 afterwards, open *Settings → Permalinks* and click **Save Changes**.

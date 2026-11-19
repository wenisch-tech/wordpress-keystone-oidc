<?php
/**
 * OIDC Client Manager
 *
 * Handles CRUD operations for OIDC clients and database table management.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class KEYSTONE_OIDC_Client_Manager {

	const TABLE_CLIENTS    = 'oidc_clients';
	const TABLE_AUTH_CODES = 'oidc_auth_codes';
	const TABLE_TOKENS     = 'oidc_tokens';
	const CACHE_GROUP      = 'keystone_oidc';
	const CACHE_ALL_CLIENTS = 'all_clients';

	/**
	 * Build a cache key for a single client.
	 *
	 * @param string $client_id Client ID.
	 * @return string
	 */
	private static function client_cache_key( $client_id ) {
		return 'client_' . $client_id;
	}

	/**
	 * Invalidate cached client entries.
	 *
	 * @param string|null $client_id Optional client ID.
	 */
	private static function invalidate_client_cache( $client_id = null ) {
		wp_cache_delete( self::CACHE_ALL_CLIENTS, self::CACHE_GROUP );
		if ( $client_id ) {
			wp_cache_delete( self::client_cache_key( $client_id ), self::CACHE_GROUP );
		}
	}

	/**
	 * Create the required database tables.
	 */
	public static function create_tables() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$clients_table = $wpdb->prefix . self::TABLE_CLIENTS;
		dbDelta(
			"CREATE TABLE {$clients_table} (
				id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				client_id     VARCHAR(64)     NOT NULL,
				client_secret VARCHAR(255)    NOT NULL,
				client_name   VARCHAR(255)    NOT NULL,
				redirect_uris LONGTEXT        NOT NULL,
				allowed_scopes VARCHAR(500)   NOT NULL DEFAULT 'openid profile email',
				client_type   VARCHAR(20)     NOT NULL DEFAULT 'confidential',
				created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				PRIMARY KEY (id),
				UNIQUE KEY client_id (client_id)
			) {$charset_collate};"
		);

		$auth_codes_table = $wpdb->prefix . self::TABLE_AUTH_CODES;
		dbDelta(
			"CREATE TABLE {$auth_codes_table} (
				id                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				code                  VARCHAR(128)    NOT NULL,
				client_id             VARCHAR(64)     NOT NULL,
				user_id               BIGINT UNSIGNED NOT NULL,
				redirect_uri          TEXT            NOT NULL,
				scope                 VARCHAR(500)    NOT NULL,
				code_challenge        VARCHAR(128)    DEFAULT NULL,
				code_challenge_method VARCHAR(10)     DEFAULT NULL,
				nonce                 VARCHAR(255)    DEFAULT NULL,
				expires_at            DATETIME        NOT NULL,
				created_at            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (id),
				UNIQUE KEY code (code)
			) {$charset_collate};"
		);

		$tokens_table = $wpdb->prefix . self::TABLE_TOKENS;
		dbDelta(
			"CREATE TABLE {$tokens_table} (
				id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				token_hash  VARCHAR(64)     NOT NULL,
				client_id   VARCHAR(64)     NOT NULL,
				user_id     BIGINT UNSIGNED NOT NULL,
				scope       VARCHAR(500)    NOT NULL,
				token_type  VARCHAR(20)     NOT NULL DEFAULT 'access',
				expires_at  DATETIME        NOT NULL,
				revoked     TINYINT(1)      NOT NULL DEFAULT 0,
				created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (id),
				UNIQUE KEY token_hash (token_hash)
			) {$charset_collate};"
		);
	}

	/**
	 * Run schema upgrades for installs that updated without re-activating.
	 * dbDelta adds the client_type column; existing rows default to 'confidential'.
	 */
	public static function maybe_upgrade() {
		if ( get_option( 'keystone_oidc_db_version' ) === KEYSTONE_OIDC_DB_VERSION ) {
			return;
		}
		self::create_tables();
		self::invalidate_client_cache();
		update_option( 'keystone_oidc_db_version', KEYSTONE_OIDC_DB_VERSION );
	}

	/**
	 * Drop the plugin database tables.
	 */
	public static function drop_tables() {
		global $wpdb;
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::TABLE_TOKENS );
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::TABLE_AUTH_CODES );
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::TABLE_CLIENTS );
		// phpcs:enable

		self::invalidate_client_cache();
	}

	/**
	 * Generate a secure random client ID.
	 *
	 * @return string
	 */
	public static function generate_client_id() {
		return 'client_' . bin2hex( random_bytes( 12 ) );
	}

	/**
	 * Generate a secure random client secret (plaintext).
	 *
	 * @return string
	 */
	public static function generate_secret_plain() {
		return bin2hex( random_bytes( 32 ) );
	}

	/**
	 * Hash a client secret for storage.
	 *
	 * @param string $plain Plaintext secret.
	 * @return string
	 */
	public static function hash_secret( $plain ) {
		return wp_hash_password( $plain );
	}

	/**
	 * Verify a client secret against its stored hash.
	 *
	 * @param string $plain  Plaintext secret to verify.
	 * @param string $hashed Stored hash.
	 * @return bool
	 */
	public static function verify_secret( $plain, $hashed ) {
		return (bool) wp_check_password( $plain, $hashed );
	}

	/**
	 * Normalise a client type. Anything other than "public" is confidential.
	 *
	 * @param string $type Requested type.
	 * @return string 'public' or 'confidential'.
	 */
	public static function sanitize_client_type( $type ) {
		return 'public' === $type ? 'public' : 'confidential';
	}

	/**
	 * Whether a client is public (cannot keep a secret; must use PKCE).
	 *
	 * @param object $client Client row.
	 * @return bool
	 */
	public static function is_public( $client ) {
		return isset( $client->client_type ) && 'public' === $client->client_type;
	}

	/**
	 * Sanitize and validate a list of redirect URIs for storage.
	 *
	 * http(s) URIs behave as before. Reverse-domain private-use schemes for
	 * native apps (RFC 8252 section 7.1, e.g. "com.example.app:/callback") are
	 * accepted for public clients only.
	 *
	 * @param array  $uris        Raw URIs.
	 * @param string $client_type 'confidential' or 'public'.
	 * @return string[]|WP_Error Clean URIs, or an error naming the rejected URI.
	 */
	public static function sanitize_redirect_uris( array $uris, $client_type = 'confidential' ) {
		$clean = array();
		foreach ( $uris as $uri ) {
			$result = self::sanitize_redirect_uri( $uri, $client_type );
			if ( '' === $result ) {
				return new WP_Error(
					'invalid_redirect_uri',
					sprintf(
						/* translators: %s: the rejected redirect URI. */
						__( 'Invalid redirect URI: %s', 'keystone-oidc' ),
						(string) $uri
					)
				);
			}
			$clean[] = $result;
		}
		return $clean;
	}

	/**
	 * Sanitize a single redirect URI.
	 *
	 * @param string $uri         Raw URI.
	 * @param string $client_type 'confidential' or 'public'.
	 * @return string Clean URI, or '' if it is not acceptable.
	 */
	public static function sanitize_redirect_uri( $uri, $client_type = 'confidential' ) {
		$uri = trim( (string) $uri );
		if ( '' === $uri ) {
			return '';
		}

		// Everything WordPress already accepts keeps working unchanged.
		$clean = esc_url_raw( $uri );
		if ( '' !== $clean ) {
			return $clean;
		}

		if ( 'public' !== $client_type ) {
			return '';
		}

		// Private-use scheme: only a reverse-domain scheme (it must contain a
		// dot) followed by "/", no whitespace, control characters or
		// fragment (RFC 6749 section 3.1.2).
		if ( preg_match( '/[\x00-\x20\x7f#]/', $uri ) ) {
			return '';
		}
		if ( ! preg_match( '#^([a-z][a-z0-9+.\-]*):/#i', $uri, $m ) ) {
			return '';
		}
		$scheme = strtolower( $m[1] );
		if ( false === strpos( $scheme, '.' ) || in_array( $scheme, array( 'javascript', 'data', 'vbscript', 'file', 'blob', 'about' ), true ) ) {
			return '';
		}

		return $uri;
	}

	/**
	 * Normalise a redirect_uri taken from a request.
	 *
	 * The result is only ever compared for exact equality with the registered
	 * URIs, so it is not rewritten. Values with control characters are dropped.
	 *
	 * @param string $uri Raw request value.
	 * @return string
	 */
	public static function normalize_request_redirect_uri( $uri ) {
		$uri = trim( (string) $uri );
		return preg_match( '/[\x00-\x1f\x7f]/', $uri ) ? '' : $uri;
	}

	/**
	 * Create a new OIDC client.
	 *
	 * @param string $name          Client name.
	 * @param array  $redirect_uris Array of redirect URIs.
	 * @param string $allowed_scopes Space-separated scopes.
	 * @param string $client_type   'confidential' (default) or 'public'.
	 * @return array|WP_Error Array with 'client_id' and 'client_secret' (plaintext) on success.
	 */
	public static function create_client( $name, array $redirect_uris, $allowed_scopes = 'openid profile email', $client_type = 'confidential' ) {
		global $wpdb;

		$redirect_uris = self::sanitize_redirect_uris( $redirect_uris, $client_type );
		if ( is_wp_error( $redirect_uris ) ) {
			return $redirect_uris;
		}

		$plain_secret = self::generate_secret_plain();
		$hashed_secret = self::hash_secret( $plain_secret );
		$client_id = self::generate_client_id();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->insert(
			$wpdb->prefix . self::TABLE_CLIENTS,
			array(
				'client_id'     => $client_id,
				'client_secret' => $hashed_secret,
				'client_name'   => sanitize_text_field( $name ),
				'redirect_uris' => wp_json_encode( $redirect_uris ),
				'allowed_scopes' => sanitize_text_field( $allowed_scopes ),
				'client_type'   => self::sanitize_client_type( $client_type ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( false === $result ) {
			return new WP_Error( 'db_error', __( 'Failed to create client.', 'keystone-oidc' ) );
		}

		self::invalidate_client_cache( $client_id );

		return array(
			'client_id'     => $client_id,
			'client_secret' => $plain_secret,
		);
	}

	/**
	 * Update an existing OIDC client.
	 *
	 * @param string $client_id      Client ID.
	 * @param string $name           Client name.
	 * @param array  $redirect_uris  Array of redirect URIs.
	 * @param string $allowed_scopes Space-separated scopes.
	 * @param string $client_type    'confidential' or 'public'.
	 * @return bool|WP_Error
	 */
	public static function update_client( $client_id, $name, array $redirect_uris, $allowed_scopes, $client_type = 'confidential' ) {
		global $wpdb;

		$redirect_uris = self::sanitize_redirect_uris( $redirect_uris, $client_type );
		if ( is_wp_error( $redirect_uris ) ) {
			return $redirect_uris;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$wpdb->prefix . self::TABLE_CLIENTS,
			array(
				'client_name'   => sanitize_text_field( $name ),
				'redirect_uris' => wp_json_encode( $redirect_uris ),
				'allowed_scopes' => sanitize_text_field( $allowed_scopes ),
				'client_type'   => self::sanitize_client_type( $client_type ),
			),
			array( 'client_id' => $client_id ),
			array( '%s', '%s', '%s', '%s' ),
			array( '%s' )
		);

		if ( false === $result ) {
			return new WP_Error( 'db_error', __( 'Failed to update client.', 'keystone-oidc' ) );
		}

		self::invalidate_client_cache( $client_id );

		return true;
	}

	/**
	 * Reset the client secret, returning the new plaintext secret.
	 *
	 * @param string $client_id Client ID.
	 * @return string|WP_Error Plaintext secret on success.
	 */
	public static function reset_secret( $client_id ) {
		global $wpdb;

		$plain_secret  = self::generate_secret_plain();
		$hashed_secret = self::hash_secret( $plain_secret );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			$wpdb->prefix . self::TABLE_CLIENTS,
			array( 'client_secret' => $hashed_secret ),
			array( 'client_id' => $client_id ),
			array( '%s' ),
			array( '%s' )
		);

		if ( false === $result ) {
			return new WP_Error( 'db_error', __( 'Failed to reset client secret.', 'keystone-oidc' ) );
		}

		self::invalidate_client_cache( $client_id );

		return $plain_secret;
	}

	/**
	 * Delete a client and all associated tokens/codes.
	 *
	 * @param string $client_id Client ID.
	 * @return bool
	 */
	public static function delete_client( $client_id ) {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete( $wpdb->prefix . self::TABLE_AUTH_CODES, array( 'client_id' => $client_id ), array( '%s' ) );
		$wpdb->delete( $wpdb->prefix . self::TABLE_TOKENS, array( 'client_id' => $client_id ), array( '%s' ) );
		$result = $wpdb->delete( $wpdb->prefix . self::TABLE_CLIENTS, array( 'client_id' => $client_id ), array( '%s' ) );
		// phpcs:enable

		self::invalidate_client_cache( $client_id );

		return false !== $result;
	}

	/**
	 * Get a client by client_id.
	 *
	 * @param string $client_id Client ID.
	 * @return object|null
	 */
	public static function get_client( $client_id ) {
		global $wpdb;

		$cache_key = self::client_cache_key( $client_id );
		$found     = false;
		$cached    = wp_cache_get( $cache_key, self::CACHE_GROUP, false, $found );
		if ( $found ) {
			return $cached;
		}

		$table = $wpdb->prefix . self::TABLE_CLIENTS;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$client = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE client_id = %s", $client_id ) );

		wp_cache_set( $cache_key, $client, self::CACHE_GROUP, 300 );

		return $client;
	}

	/**
	 * Get all clients.
	 *
	 * @return array
	 */
	public static function get_all_clients() {
		global $wpdb;

		$found  = false;
		$cached = wp_cache_get( self::CACHE_ALL_CLIENTS, self::CACHE_GROUP, false, $found );
		if ( $found ) {
			return $cached;
		}

		$table = $wpdb->prefix . self::TABLE_CLIENTS;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$clients = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC" );

		wp_cache_set( self::CACHE_ALL_CLIENTS, $clients, self::CACHE_GROUP, 300 );

		return $clients;
	}

	/**
	 * Validate a client's redirect URI.
	 *
	 * @param string $client_id    Client ID.
	 * @param string $redirect_uri URI to validate.
	 * @return bool
	 */
	public static function validate_redirect_uri( $client_id, $redirect_uri ) {
		$client = self::get_client( $client_id );
		if ( ! $client ) {
			return false;
		}

		$allowed = json_decode( $client->redirect_uris, true );
		if ( ! is_array( $allowed ) ) {
			return false;
		}

		return in_array( $redirect_uri, $allowed, true );
	}

	/**
	 * Get redirect URIs as array from a client object.
	 *
	 * @param object $client Client DB row.
	 * @return array
	 */
	public static function get_redirect_uris( $client ) {
		$uris = json_decode( $client->redirect_uris, true );
		return is_array( $uris ) ? $uris : array();
	}
}

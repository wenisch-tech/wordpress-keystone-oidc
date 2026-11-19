<?php
/**
 * OIDC Token Manager
 *
 * Handles JWT generation/validation, authorization codes, and token storage.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class KEYSTONE_OIDC_Token_Manager {

	const OPTION_PRIVATE_KEY = 'keystone_oidc_private_key';
	const OPTION_PUBLIC_KEY  = 'keystone_oidc_public_key';
	const OPTION_KEY_ID      = 'keystone_oidc_key_id';
	const CACHE_GROUP        = 'keystone_oidc';

	const AUTH_CODE_LIFETIME    = 600;       // 10 minutes.
	const ACCESS_TOKEN_LIFETIME = 3600;      // 1 hour.
	const REFRESH_TOKEN_LIFETIME = 2592000;  // 30 days.

	/**
	 * Build cache key for authorization code record.
	 *
	 * @param string $code Authorization code.
	 * @return string
	 */
	private static function auth_code_cache_key( $code ) {
		return 'auth_code_' . $code;
	}

	/**
	 * Build cache key for token lookup.
	 *
	 * @param string $token_type Token type.
	 * @param string $hash       Token hash.
	 * @return string
	 */
	private static function token_cache_key( $token_type, $hash ) {
		return 'token_' . $token_type . '_' . $hash;
	}

	/**
	 * Generate and store RSA key pair.
	 *
	 * @return bool
	 */
	public static function generate_keys() {
		$config = array(
			'digest_alg'       => 'sha256',
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		);

		$res = openssl_pkey_new( $config );
		if ( ! $res ) {
			return false;
		}

		openssl_pkey_export( $res, $private_key );
		$details    = openssl_pkey_get_details( $res );
		$public_key = $details['key'];

		update_option( self::OPTION_PRIVATE_KEY, $private_key );
		update_option( self::OPTION_PUBLIC_KEY, $public_key );
		update_option( self::OPTION_KEY_ID, bin2hex( random_bytes( 8 ) ) );

		return true;
	}

	/**
	 * Get the stored private key resource.
	 *
	 * @return resource|\OpenSSLAsymmetricKey|false
	 */
	public static function get_private_key() {
		$pem = get_option( self::OPTION_PRIVATE_KEY, '' );
		if ( ! $pem ) {
			return false;
		}
		return openssl_pkey_get_private( $pem );
	}

	/**
	 * Get the stored public key PEM.
	 *
	 * @return string
	 */
	public static function get_public_key_pem() {
		return get_option( self::OPTION_PUBLIC_KEY, '' );
	}

	/**
	 * Get the current key ID.
	 *
	 * @return string
	 */
	public static function get_key_id() {
		return get_option( self::OPTION_KEY_ID, 'key1' );
	}

	/**
	 * Base64-URL encode (without padding).
	 *
	 * @param string $data Binary data.
	 * @return string
	 */
	public static function base64url_encode( $data ) {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	/**
	 * Base64-URL decode.
	 *
	 * @param string $data Encoded data.
	 * @return string
	 */
	public static function base64url_decode( $data ) {
		$remainder  = strlen( $data ) % 4;
		$pad_length = $remainder === 0 ? strlen( $data ) : strlen( $data ) + 4 - $remainder;
		$padded     = str_pad( strtr( $data, '-_', '+/' ), $pad_length, '=', STR_PAD_RIGHT );
		return base64_decode( $padded );
	}

	/**
	 * Create and sign a JWT using RS256.
	 *
	 * @param array $payload JWT payload.
	 * @return string|false Signed JWT or false on error.
	 */
	public static function create_jwt( array $payload ) {
		$private_key = self::get_private_key();
		if ( ! $private_key ) {
			return false;
		}

		$header = array(
			'alg' => 'RS256',
			'typ' => 'JWT',
			'kid' => self::get_key_id(),
		);

		$b64_header  = self::base64url_encode( wp_json_encode( $header ) );
		$b64_payload = self::base64url_encode( wp_json_encode( $payload ) );
		$signing_input = $b64_header . '.' . $b64_payload;

		$signature = '';
		$signed    = openssl_sign( $signing_input, $signature, $private_key, OPENSSL_ALGO_SHA256 );

		if ( ! $signed ) {
			return false;
		}

		return $signing_input . '.' . self::base64url_encode( $signature );
	}

	/**
	 * Decode and verify a JWT (RS256).
	 *
	 * @param string $token JWT string.
	 * @return array|WP_Error Decoded payload or error.
	 */
	public static function verify_jwt( $token ) {
		$parts = explode( '.', $token );
		if ( count( $parts ) !== 3 ) {
			return new WP_Error( 'invalid_token', 'Malformed token.' );
		}

		list( $b64_header, $b64_payload, $b64_sig ) = $parts;

		$signing_input = $b64_header . '.' . $b64_payload;
		$signature     = self::base64url_decode( $b64_sig );

		$public_key_pem = self::get_public_key_pem();
		$public_key     = openssl_pkey_get_public( $public_key_pem );
		if ( ! $public_key ) {
			return new WP_Error( 'key_error', 'Cannot load public key.' );
		}

		$result = openssl_verify( $signing_input, $signature, $public_key, OPENSSL_ALGO_SHA256 );
		if ( 1 !== $result ) {
			return new WP_Error( 'invalid_signature', 'Token signature is invalid.' );
		}

		$payload = json_decode( self::base64url_decode( $b64_payload ), true );
		if ( ! is_array( $payload ) ) {
			return new WP_Error( 'invalid_payload', 'Cannot decode token payload.' );
		}

		if ( isset( $payload['exp'] ) && time() > $payload['exp'] ) {
			return new WP_Error( 'token_expired', 'Token has expired.' );
		}

		return $payload;
	}

	/**
	 * Build the JWKS (JSON Web Key Set) from the stored public key.
	 *
	 * @return array
	 */
	public static function get_jwks() {
		$public_key_pem = self::get_public_key_pem();
		if ( ! $public_key_pem ) {
			return array( 'keys' => array() );
		}

		$public_key = openssl_pkey_get_public( $public_key_pem );
		$details    = openssl_pkey_get_details( $public_key );

		if ( ! $details || ! isset( $details['rsa'] ) ) {
			return array( 'keys' => array() );
		}

		$rsa = $details['rsa'];

		$jwk = array(
			'kty' => 'RSA',
			'use' => 'sig',
			'alg' => 'RS256',
			'kid' => self::get_key_id(),
			'n'   => self::base64url_encode( $rsa['n'] ),
			'e'   => self::base64url_encode( $rsa['e'] ),
		);

		return array( 'keys' => array( $jwk ) );
	}

	/**
	 * Generate an authorization code and store it.
	 *
	 * @param string $client_id             Client ID.
	 * @param int    $user_id               WordPress user ID.
	 * @param string $redirect_uri          Redirect URI.
	 * @param string $scope                 Scope string.
	 * @param string $nonce                 Nonce (optional).
	 * @param string $code_challenge        PKCE code challenge (optional).
	 * @param string $code_challenge_method PKCE method (optional).
	 * @return string The authorization code.
	 */
	public static function generate_auth_code( $client_id, $user_id, $redirect_uri, $scope, $nonce = null, $code_challenge = null, $code_challenge_method = null ) {
		global $wpdb;

		$code       = bin2hex( random_bytes( 32 ) );
		$expires_at = gmdate( 'Y-m-d H:i:s', time() + self::get_lifetime( 'auth_code', $client_id ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_AUTH_CODES,
			array(
				'code'                  => $code,
				'client_id'             => $client_id,
				'user_id'               => $user_id,
				'redirect_uri'          => $redirect_uri,
				'scope'                 => $scope,
				'code_challenge'        => $code_challenge,
				'code_challenge_method' => $code_challenge_method,
				'nonce'                 => $nonce,
				'expires_at'            => $expires_at,
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		return $code;
	}

	/**
	 * RFC 7636 verifier/challenge format: 43-128 unreserved characters.
	 *
	 * @param string $value Value to check.
	 * @return bool
	 */
	public static function is_valid_pkce_value( $value ) {
		return (bool) preg_match( '/^[A-Za-z0-9\-._~]{43,128}$/', (string) $value );
	}

	/**
	 * Consume an authorization code (validate and delete).
	 *
	 * @param string $code         Authorization code.
	 * @param string $client_id    Client ID.
	 * @param string $redirect_uri Redirect URI.
	 * @param string $code_verifier PKCE verifier (optional).
	 * @return object|WP_Error Auth code DB row or error.
	 */
	public static function consume_auth_code( $code, $client_id, $redirect_uri, $code_verifier = null, $require_pkce = false ) {
		global $wpdb;
		$cache_key = self::auth_code_cache_key( $code );
		$found     = false;
		$row       = wp_cache_get( $cache_key, self::CACHE_GROUP, false, $found );

		$table = $wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_AUTH_CODES;
		if ( ! $found ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE code = %s", $code ) );
			wp_cache_set( $cache_key, $row, self::CACHE_GROUP, 60 );
		}

		if ( ! $row ) {
			return new WP_Error( 'invalid_grant', 'Authorization code not found.' );
		}

		// Always delete the code immediately (single use).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->delete( $table, array( 'code' => $code ), array( '%s' ) );
		wp_cache_delete( $cache_key, self::CACHE_GROUP );

		if ( strtotime( $row->expires_at ) < time() ) {
			return new WP_Error( 'invalid_grant', 'Authorization code has expired.' );
		}

		if ( $row->client_id !== $client_id ) {
			return new WP_Error( 'invalid_grant', 'Client ID mismatch.' );
		}

		if ( $row->redirect_uri !== $redirect_uri ) {
			return new WP_Error( 'invalid_grant', 'Redirect URI mismatch.' );
		}

		// Public clients must always have used PKCE.
		if ( $require_pkce && ! $row->code_challenge ) {
			return new WP_Error( 'invalid_grant', 'PKCE is required for public clients.' );
		}

		// PKCE verification.
		if ( $row->code_challenge ) {
			if ( ! $code_verifier ) {
				return new WP_Error( 'invalid_grant', 'code_verifier required.' );
			}
			if ( ! self::is_valid_pkce_value( $code_verifier ) ) {
				return new WP_Error( 'invalid_grant', 'Malformed code_verifier.' );
			}
			if ( 'S256' === $row->code_challenge_method ) {
				$challenge = self::base64url_encode( hash( 'sha256', $code_verifier, true ) );
			} else {
				$challenge = $code_verifier;
			}
			if ( ! hash_equals( $row->code_challenge, $challenge ) ) {
				return new WP_Error( 'invalid_grant', 'PKCE verification failed.' );
			}
		}

		return $row;
	}

	/**
	 * Issue an access token JWT and store a reference.
	 *
	 * @param string $client_id Client ID.
	 * @param int    $user_id   WordPress user ID.
	 * @param string $scope     Scope string.
	 * @param string $nonce     Nonce for ID token (optional).
	 * @return array Array with 'access_token', 'id_token', 'refresh_token', 'expires_in'.
	 */
	public static function issue_tokens( $client_id, $user_id, $scope, $nonce = null ) {
		$issuer  = self::get_issuer();
		$now     = time();
		$scopes  = explode( ' ', $scope );
		$user    = get_userdata( $user_id );
		$access_lifetime  = self::get_lifetime( 'access_token', $client_id );
		$refresh_lifetime = self::get_lifetime( 'refresh_token', $client_id );

		// --- Access token ---
		$access_payload = array(
			'iss'   => $issuer,
			'sub'   => (string) $user_id,
			'aud'   => $client_id,
			'iat'   => $now,
			'exp'   => $now + $access_lifetime,
			'jti'   => bin2hex( random_bytes( 16 ) ),
			'scope' => $scope,
		);
		$access_payload = self::apply_claims_filter( 'keystone_oidc_access_token_claims', $access_payload, $user, $client_id, $scopes );
		$access_token   = self::create_jwt( $access_payload );

		// Store a hash reference for revocation checks.
		self::store_token_record( hash( 'sha256', $access_token ), $client_id, $user_id, $scope, 'access', $now + $access_lifetime );

		// --- ID token ---
		$id_payload = array(
			'iss' => $issuer,
			'sub' => (string) $user_id,
			'aud' => $client_id,
			'iat' => $now,
			'exp' => $now + $access_lifetime,
			'jti' => bin2hex( random_bytes( 16 ) ),
		);
		if ( $nonce ) {
			$id_payload['nonce'] = $nonce;
		}
		if ( $user ) {
			$id_payload = array_merge( $id_payload, self::build_user_claims( $user, $scopes ) );
		}
		$id_payload = self::apply_claims_filter( 'keystone_oidc_id_token_claims', $id_payload, $user, $client_id, $scopes );
		$id_token   = self::create_jwt( $id_payload );

		// --- Refresh token ---
		$refresh_token      = bin2hex( random_bytes( 32 ) );
		$refresh_token_hash = hash( 'sha256', $refresh_token );
		self::store_token_record( $refresh_token_hash, $client_id, $user_id, $scope, 'refresh', $now + $refresh_lifetime );

		return array(
			'access_token'  => $access_token,
			'id_token'      => $id_token,
			'refresh_token' => $refresh_token,
			'expires_in'    => $access_lifetime,
		);
	}

	/**
	 * Get a (filterable) lifetime in seconds.
	 *
	 * @param string $type      'auth_code', 'access_token' or 'refresh_token'.
	 * @param string $client_id Client ID.
	 * @return int Seconds.
	 */
	public static function get_lifetime( $type, $client_id = '' ) {
		$defaults = array(
			'auth_code'     => self::AUTH_CODE_LIFETIME,
			'access_token'  => self::ACCESS_TOKEN_LIFETIME,
			'refresh_token' => self::REFRESH_TOKEN_LIFETIME,
		);
		$default = isset( $defaults[ $type ] ) ? $defaults[ $type ] : 3600;

		/**
		 * Filters a token lifetime in seconds.
		 *
		 * The dynamic part is auth_code, access_token or refresh_token.
		 *
		 * @param int    $seconds   Lifetime in seconds.
		 * @param string $client_id Client ID.
		 */
		$seconds = (int) apply_filters( "keystone_oidc_{$type}_lifetime", $default, $client_id );
		return $seconds > 0 ? $seconds : $default;
	}

	/**
	 * Apply a claims filter while keeping protocol-critical claims intact.
	 *
	 * @param string       $hook      Filter name.
	 * @param array        $claims    Claims.
	 * @param WP_User|bool $user      User (false if not found).
	 * @param string       $client_id Client ID.
	 * @param array        $scopes    Granted scopes.
	 * @return array Filtered claims.
	 */
	public static function apply_claims_filter( $hook, array $claims, $user, $client_id, array $scopes ) {
		$filtered = apply_filters( $hook, $claims, $user, $client_id, $scopes );
		if ( ! is_array( $filtered ) ) {
			return $claims;
		}
		foreach ( array( 'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nonce' ) as $key ) {
			if ( array_key_exists( $key, $claims ) ) {
				$filtered[ $key ] = $claims[ $key ];
			} else {
				unset( $filtered[ $key ] );
			}
		}
		return $filtered;
	}

	/**
	 * Revoke all tokens of a user (optionally limited to one client).
	 *
	 * @param int         $user_id   WordPress user ID.
	 * @param string|null $client_id Client ID, or null for all clients.
	 * @return int Number of token records revoked.
	 */
	public static function revoke_user_tokens( $user_id, $client_id = null ) {
		global $wpdb;
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return 0;
		}
		$table = $wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_TOKENS;

		// Collect hashes first so the object cache can be invalidated.
		if ( null === $client_id ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT token_hash, token_type FROM {$table} WHERE user_id = %d AND revoked = 0", $user_id ) );
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT token_hash, token_type FROM {$table} WHERE user_id = %d AND client_id = %s AND revoked = 0", $user_id, $client_id ) );
		}

		$count = 0;
		foreach ( (array) $rows as $row ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->update( $table, array( 'revoked' => 1 ), array( 'token_hash' => $row->token_hash ), array( '%d' ), array( '%s' ) );
			wp_cache_delete( self::token_cache_key( $row->token_type, $row->token_hash ), self::CACHE_GROUP );
			++$count;
		}

		/**
		 * Fires after a user's tokens were revoked.
		 *
		 * @param int         $user_id   User ID.
		 * @param string|null $client_id Client ID or null for all clients.
		 * @param int         $count     Number of revoked token records.
		 */
		do_action( 'keystone_oidc_tokens_revoked', $user_id, $client_id, $count );

		return $count;
	}

	/**
	 * Revoke tokens when a user's password changes.
	 *
	 * @param int     $user_id       User ID.
	 * @param WP_User $old_user_data User data before the update.
	 */
	public static function on_profile_update( $user_id, $old_user_data ) {
		$user = get_userdata( $user_id );
		if ( $user && $old_user_data && $user->user_pass !== $old_user_data->user_pass ) {
			self::revoke_user_tokens( $user_id );
		}
	}

	/**
	 * Revoke tokens when a user is deleted.
	 *
	 * @param int $user_id User ID.
	 */
	public static function on_delete_user( $user_id ) {
		self::revoke_user_tokens( $user_id );
	}

	/**
	 * Revoke tokens after a password reset.
	 *
	 * @param WP_User $user User.
	 */
	public static function on_password_reset( $user ) {
		self::revoke_user_tokens( $user->ID );
	}

	/**
	 * Build the user claims released for the given scopes.
	 *
	 * Shared by the ID token and the userinfo endpoint.
	 *
	 * @param WP_User $user   WordPress user.
	 * @param array   $scopes Granted scopes.
	 * @return array Claims.
	 */
	public static function build_user_claims( $user, $scopes ) {
		$claims = array();

		if ( in_array( 'profile', $scopes, true ) ) {
			$claims['name']               = $user->display_name;
			$claims['given_name']         = $user->first_name;
			$claims['family_name']        = $user->last_name;
			$claims['preferred_username'] = $user->user_login;
		}
		if ( in_array( 'email', $scopes, true ) ) {
			$claims['email']          = $user->user_email;
			$claims['email_verified'] = true;
		}
		if ( in_array( 'roles', $scopes, true ) ) {
			/**
			 * Filters the roles released in the "roles" claim.
			 *
			 * @param string[] $roles Role slugs of the user.
			 * @param WP_User  $user  The user.
			 */
			$roles           = apply_filters( 'keystone_oidc_user_roles', array_values( (array) $user->roles ), $user );
			$claims['roles'] = array_values( array_map( 'strval', (array) $roles ) );
		}

		return $claims;
	}

	/**
	 * Store a token record in the database.
	 *
	 * @param string $hash       SHA-256 hash of the token.
	 * @param string $client_id  Client ID.
	 * @param int    $user_id    WordPress user ID.
	 * @param string $scope      Scope string.
	 * @param string $token_type 'access' or 'refresh'.
	 * @param int    $expires    Unix timestamp when the token expires.
	 */
	private static function store_token_record( $hash, $client_id, $user_id, $scope, $token_type, $expires ) {
		global $wpdb;
		$expires_at = gmdate( 'Y-m-d H:i:s', $expires );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_TOKENS,
			array(
				'token_hash' => $hash,
				'client_id'  => $client_id,
				'user_id'    => $user_id,
				'scope'      => $scope,
				'token_type' => $token_type,
				'expires_at' => $expires_at,
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		$record = (object) array(
			'token_hash' => $hash,
			'client_id'  => $client_id,
			'user_id'    => $user_id,
			'scope'      => $scope,
			'token_type' => $token_type,
			'expires_at' => $expires_at,
			'revoked'    => 0,
		);
		wp_cache_set( self::token_cache_key( $token_type, $hash ), $record, self::CACHE_GROUP, 300 );
	}

	/**
	 * Validate an access token and return its record.
	 *
	 * @param string $access_token Bearer token.
	 * @return array|WP_Error Decoded payload or error.
	 */
	public static function validate_access_token( $access_token ) {
		global $wpdb;

		$payload = self::verify_jwt( $access_token );
		if ( is_wp_error( $payload ) ) {
			return $payload;
		}

		// Check revocation.
		$hash  = hash( 'sha256', $access_token );
		$cache_key = self::token_cache_key( 'access', $hash );
		$found     = false;
		$record    = wp_cache_get( $cache_key, self::CACHE_GROUP, false, $found );
		if ( ! $found ) {
			$table = $wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_TOKENS;
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery
			$record = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE token_hash = %s AND token_type = 'access'", $hash ) );
			wp_cache_set( $cache_key, $record, self::CACHE_GROUP, 300 );
		}

		if ( ! $record ) {
			return new WP_Error( 'invalid_token', 'Token not found.' );
		}
		if ( $record->revoked ) {
			return new WP_Error( 'invalid_token', 'Token has been revoked.' );
		}

		return $payload;
	}

	/**
	 * Use a refresh token to issue new tokens.
	 *
	 * @param string $refresh_token Refresh token string.
	 * @param string $client_id     Client ID.
	 * @return array|WP_Error New tokens or error.
	 */
	public static function refresh_tokens( $refresh_token, $client_id ) {
		global $wpdb;

		$hash  = hash( 'sha256', $refresh_token );
		$cache_key = self::token_cache_key( 'refresh', $hash );
		$found     = false;
		$record    = wp_cache_get( $cache_key, self::CACHE_GROUP, false, $found );
		$table = $wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_TOKENS;
		if ( ! $found ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery
			$record = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE token_hash = %s AND token_type = 'refresh'", $hash ) );
			wp_cache_set( $cache_key, $record, self::CACHE_GROUP, 300 );
		}

		if ( ! $record ) {
			return new WP_Error( 'invalid_grant', 'Refresh token not found.' );
		}
		if ( $record->revoked ) {
			return new WP_Error( 'invalid_grant', 'Refresh token has been revoked.' );
		}
		if ( strtotime( $record->expires_at ) < time() ) {
			return new WP_Error( 'invalid_grant', 'Refresh token has expired.' );
		}
		if ( $record->client_id !== $client_id ) {
			return new WP_Error( 'invalid_grant', 'Client ID mismatch.' );
		}

		$user = get_userdata( $record->user_id );
		if ( ! $user ) {
			return new WP_Error( 'invalid_grant', 'User no longer exists.' );
		}

		/**
		 * Filters whether a refresh token may still be exchanged.
		 *
		 * Return false or a WP_Error to reject with invalid_grant.
		 *
		 * @param bool   $allowed   Whether refreshing is allowed.
		 * @param int    $user_id   User ID.
		 * @param string $client_id Client ID.
		 */
		$allowed = apply_filters( 'keystone_oidc_refresh_allowed', true, (int) $record->user_id, $client_id );
		if ( is_wp_error( $allowed ) || ! $allowed ) {
			return new WP_Error( 'invalid_grant', is_wp_error( $allowed ) ? $allowed->get_error_message() : 'Refresh not allowed.' );
		}

		// Revoke old refresh token.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update( $table, array( 'revoked' => 1 ), array( 'token_hash' => $hash ), array( '%d' ), array( '%s' ) );
		if ( $record ) {
			$record->revoked = 1;
			wp_cache_set( $cache_key, $record, self::CACHE_GROUP, 60 );
		}

		return self::issue_tokens( $client_id, $record->user_id, $record->scope );
	}

	/**
	 * Get the OIDC issuer URL.
	 *
	 * @return string
	 */
	public static function get_issuer() {
		$site_url       = untrailingslashit( get_bloginfo( 'url' ) );
		$default_issuer = untrailingslashit( trailingslashit( $site_url ) . 'wenisch-tech/keystone-oidc' );
		$issuer         = untrailingslashit( get_option( 'keystone_oidc_issuer', '' ) );

		if ( '' === $issuer || $site_url === $issuer ) {
			return $default_issuer;
		}

		return $issuer;
	}

	/**
	 * Clean up expired auth codes and tokens.
	 */
	public static function cleanup_expired() {
		global $wpdb;
		$now  = gmdate( 'Y-m-d H:i:s' );

		$auth_table  = $wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_AUTH_CODES;
		$token_table = $wpdb->prefix . KEYSTONE_OIDC_Client_Manager::TABLE_TOKENS;

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$auth_table} WHERE expires_at < %s", $now ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$token_table} WHERE expires_at < %s AND revoked = 1", $now ) );
		// phpcs:enable
	}
}

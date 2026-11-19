<?php
/**
 * OIDC Provider - Main Class
 *
 * Registers rewrite rules, handles activation/deactivation,
 * and dispatches OIDC endpoint requests.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sanitize an OAuth2 state parameter without changing semantic content.
 *
 * RFC 6749 requires the authorization server to return `state` unchanged.
 * So we avoid broad text sanitizers that can rewrite characters (for example,
 * dropping encoded padding), and only strip control bytes to prevent header or
 * log injection vectors.
 *
 * @param string $state Raw state value.
 * @return string Sanitized state.
 */
function keystone_oidc_sanitize_oauth2_state( $state ) {
	$state = (string) $state;

	// Keep state stable, only remove control characters.
	$state = preg_replace( '/[\x00-\x1F\x7F]/', '', $state );

	// Cap size to avoid abuse while staying far above practical OAuth2 states.
	if ( strlen( $state ) > 2048 ) {
		return '';
	}

	return $state;
}

class KEYSTONE_OIDC_Provider {
	const ENDPOINT_BASE_PATH = 'wenisch-tech/keystone-oidc';

	/**
	 * Get endpoint base path relative to site root.
	 *
	 * @return string
	 */
	public static function get_endpoint_base_path() {
		return trailingslashit( self::ENDPOINT_BASE_PATH );
	}

	/**
	 * Build an absolute endpoint URL.
	 *
	 * @param string $relative_path Endpoint path relative to the endpoint base path.
	 * @return string
	 */
	public static function get_endpoint_url( $relative_path ) {
		$site_base = trailingslashit( get_bloginfo( 'url' ) );
		return $site_base . self::get_endpoint_base_path() . ltrim( $relative_path, '/' );
	}

	public function __construct() {
		add_action( 'plugins_loaded', array( 'KEYSTONE_OIDC_Client_Manager', 'maybe_upgrade' ) );
		add_action( 'init', array( $this, 'register_rewrite_rules' ) );
		add_filter( 'query_vars', array( $this, 'add_query_vars' ) );
		add_filter( 'redirect_canonical', array( $this, 'disable_canonical_redirect_for_oidc' ), 10, 2 );
		add_action( 'template_redirect', array( $this, 'handle_request' ) );
		add_action( 'delete_user', array( 'KEYSTONE_OIDC_Token_Manager', 'on_delete_user' ) );
		add_action( 'after_password_reset', array( 'KEYSTONE_OIDC_Token_Manager', 'on_password_reset' ) );
		add_action( 'profile_update', array( 'KEYSTONE_OIDC_Token_Manager', 'on_profile_update' ), 10, 2 );
		add_action( 'wp_scheduled_delete', array( 'KEYSTONE_OIDC_Token_Manager', 'cleanup_expired' ) );
	}

	/**
	 * Prevent WordPress from adding trailing-slash redirects on OIDC endpoints.
	 *
	 * OAuth clients send Authorization headers to token/userinfo endpoints. A
	 * canonical 301 can cause those headers to be dropped by the HTTP client.
	 *
	 * @param string|false $redirect_url  Canonical redirect URL.
	 * @param string       $requested_url Requested URL.
	 * @return string|false
	 */
	public function disable_canonical_redirect_for_oidc( $redirect_url, $requested_url ) {
		$requested_path = wp_parse_url( $requested_url, PHP_URL_PATH );
		$base_path      = wp_parse_url( home_url( '/' . self::get_endpoint_base_path() ), PHP_URL_PATH );

		if ( $requested_path && $base_path && 0 === strpos( untrailingslashit( $requested_path ), untrailingslashit( $base_path ) ) ) {
			return false;
		}

		return $redirect_url;
	}

	/**
	 * Plugin activation: create tables, generate keys, flush rewrite rules.
	 */
	public static function activate() {
		KEYSTONE_OIDC_Client_Manager::create_tables();
		if ( ! get_option( KEYSTONE_OIDC_Token_Manager::OPTION_PRIVATE_KEY ) ) {
			KEYSTONE_OIDC_Token_Manager::generate_keys();
		}
		self::register_rewrite_rules_static();
		flush_rewrite_rules();
	}

	/**
	 * Plugin deactivation: flush rewrite rules.
	 */
	public static function deactivate() {
		flush_rewrite_rules();
	}

	/**
	 * Register OIDC rewrite rules (instance method for 'init' hook).
	 */
	public function register_rewrite_rules() {
		self::register_rewrite_rules_static();
	}

	/**
	 * Register OIDC rewrite rules (static, so activation can call it too).
	 */
	public static function register_rewrite_rules_static() {
		$endpoint_base = untrailingslashit( self::get_endpoint_base_path() );

		add_rewrite_rule( '^' . $endpoint_base . '/\.well-known/openid-configuration/?$', 'index.php?oidc_endpoint=discovery', 'top' );
		add_rewrite_rule( '^' . $endpoint_base . '/oauth/authorize/?$', 'index.php?oidc_endpoint=authorize', 'top' );
		add_rewrite_rule( '^' . $endpoint_base . '/oauth/token/?$', 'index.php?oidc_endpoint=token', 'top' );
		add_rewrite_rule( '^' . $endpoint_base . '/oauth/userinfo/?$', 'index.php?oidc_endpoint=userinfo', 'top' );
		add_rewrite_rule( '^' . $endpoint_base . '/oauth/jwks/?$', 'index.php?oidc_endpoint=jwks', 'top' );

		// Compatibility for clients that derive Keycloak-style paths from the
		// custom issuer URI. Discovery intentionally advertises only /oauth/*.
		add_rewrite_rule( '^' . $endpoint_base . '/protocol/openid-connect/auth/?$', 'index.php?oidc_endpoint=authorize', 'top' );
		add_rewrite_rule( '^' . $endpoint_base . '/protocol/openid-connect/token/?$', 'index.php?oidc_endpoint=token', 'top' );
		add_rewrite_rule( '^' . $endpoint_base . '/protocol/openid-connect/userinfo/?$', 'index.php?oidc_endpoint=userinfo', 'top' );
		add_rewrite_rule( '^' . $endpoint_base . '/protocol/openid-connect/certs/?$', 'index.php?oidc_endpoint=jwks', 'top' );
	}

	/**
	 * Register the custom query variable.
	 *
	 * @param array $vars Existing query vars.
	 * @return array
	 */
	public function add_query_vars( $vars ) {
		$vars[] = 'oidc_endpoint';
		return $vars;
	}

	/**
	 * Route requests to the appropriate handler.
	 */
	public function handle_request() {
		$endpoint = get_query_var( 'oidc_endpoint' );
		if ( ! $endpoint ) {
			return;
		}

		switch ( $endpoint ) {
			case 'discovery':
				$this->handle_discovery();
				break;
			case 'authorize':
				$this->handle_authorize();
				break;
			case 'token':
				$this->handle_token();
				break;
			case 'userinfo':
				$this->handle_userinfo();
				break;
			case 'jwks':
				$this->handle_jwks();
				break;
			default:
				$this->send_json_error( array( 'error' => 'not_found' ), 404 );
		}
	}

	// -------------------------------------------------------------------------
	// Discovery
	// -------------------------------------------------------------------------

	private function handle_discovery() {
		$issuer = KEYSTONE_OIDC_Token_Manager::get_issuer();

		$discovery = array(
			'issuer'                                => $issuer,
			'authorization_endpoint'                => self::get_endpoint_url( 'oauth/authorize' ),
			'token_endpoint'                        => self::get_endpoint_url( 'oauth/token' ),
			'userinfo_endpoint'                     => self::get_endpoint_url( 'oauth/userinfo' ),
			'jwks_uri'                              => self::get_endpoint_url( 'oauth/jwks' ),
			'scopes_supported'                      => array( 'openid', 'profile', 'email', 'roles' ),
			'response_types_supported'              => array( 'code' ),
			'grant_types_supported'                 => array( 'authorization_code', 'refresh_token' ),
			'subject_types_supported'               => array( 'public' ),
			'id_token_signing_alg_values_supported' => array( 'RS256' ),
			'token_endpoint_auth_methods_supported' => array( 'client_secret_basic', 'client_secret_post', 'none' ),
			'claims_supported'                      => array( 'sub', 'iss', 'aud', 'iat', 'exp', 'name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified', 'roles' ),
			'code_challenge_methods_supported'      => array( 'S256', 'plain' ),
		);

		$this->send_json( $discovery );
	}

	// -------------------------------------------------------------------------
	// Authorization Endpoint
	// -------------------------------------------------------------------------

	private function handle_authorize() {
		// OAuth2 browser redirects are secured by the state parameter. The consent
		// form POST is protected by the WordPress nonce verified below.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
		$response_type         = isset( $_GET['response_type'] ) ? sanitize_text_field( wp_unslash( $_GET['response_type'] ) ) : '';
		$client_id             = isset( $_GET['client_id'] ) ? sanitize_text_field( wp_unslash( $_GET['client_id'] ) ) : '';
		$redirect_uri          = isset( $_GET['redirect_uri'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_uri'] ) ) : '';
		$scope                 = isset( $_GET['scope'] ) ? sanitize_text_field( wp_unslash( $_GET['scope'] ) ) : 'openid';
		$state                 = isset( $_GET['state'] ) ? keystone_oidc_sanitize_oauth2_state( wp_unslash( $_GET['state'] ) ) : '';
		$nonce                 = isset( $_GET['nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['nonce'] ) ) : null;
		$code_challenge        = isset( $_GET['code_challenge'] ) ? sanitize_text_field( wp_unslash( $_GET['code_challenge'] ) ) : null;
		$code_challenge_method = isset( $_GET['code_challenge_method'] ) ? sanitize_text_field( wp_unslash( $_GET['code_challenge_method'] ) ) : null;
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$state                 = isset( $_POST['state'] ) ? keystone_oidc_sanitize_oauth2_state( wp_unslash( $_POST['state'] ) ) : $state;
			$nonce                 = isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : $nonce;
			$code_challenge        = isset( $_POST['code_challenge'] ) ? sanitize_text_field( wp_unslash( $_POST['code_challenge'] ) ) : $code_challenge;
			$code_challenge_method = isset( $_POST['code_challenge_method'] ) ? sanitize_text_field( wp_unslash( $_POST['code_challenge_method'] ) ) : $code_challenge_method;
		}
		// phpcs:enable

		if ( 'code' !== $response_type ) {
			$this->redirect_with_error( $redirect_uri, 'unsupported_response_type', 'Only "code" response_type is supported.', $state );
			return;
		}

		$client = KEYSTONE_OIDC_Client_Manager::get_client( $client_id );
		if ( ! $client ) {
			$this->send_json_error( array( 'error' => 'invalid_client', 'error_description' => 'Unknown client.' ), 400 );
			return;
		}

		if ( ! KEYSTONE_OIDC_Client_Manager::validate_redirect_uri( $client_id, $redirect_uri ) ) {
			$this->send_json_error( array( 'error' => 'invalid_request', 'error_description' => 'Invalid redirect_uri.' ), 400 );
			return;
		}

		// PKCE parameter validation (RFC 7636).
		if ( null !== $code_challenge_method && ! in_array( $code_challenge_method, array( 'S256', 'plain' ), true ) ) {
			$this->redirect_with_error( $redirect_uri, 'invalid_request', 'Unsupported code_challenge_method.', $state );
			return;
		}
		if ( $code_challenge && ! KEYSTONE_OIDC_Token_Manager::is_valid_pkce_value( $code_challenge ) ) {
			$this->redirect_with_error( $redirect_uri, 'invalid_request', 'Malformed code_challenge.', $state );
			return;
		}
		if ( KEYSTONE_OIDC_Client_Manager::is_public( $client ) && ( ! $code_challenge || 'S256' !== $code_challenge_method ) ) {
			$this->redirect_with_error( $redirect_uri, 'invalid_request', 'Public clients must use PKCE with code_challenge_method=S256.', $state );
			return;
		}

		$requested_scopes = explode( ' ', $scope );
		if ( ! in_array( 'openid', $requested_scopes, true ) ) {
			$this->redirect_with_error( $redirect_uri, 'invalid_scope', 'The "openid" scope is required.', $state );
			return;
		}

		// Only grant scopes the client is allowed to use ("openid" is always allowed).
		$allowed_scopes = array_merge( array( 'openid' ), explode( ' ', (string) $client->allowed_scopes ) );
		$scope          = implode( ' ', array_values( array_intersect( $requested_scopes, $allowed_scopes ) ) );

		if ( ! is_user_logged_in() ) {
			$authorize_params = array_filter(
				array(
					'response_type'         => $response_type,
					'client_id'             => $client_id,
					'redirect_uri'          => $redirect_uri,
					'scope'                 => $scope,
					'state'                 => $state,
					'nonce'                 => $nonce,
					'code_challenge'        => $code_challenge,
					'code_challenge_method' => $code_challenge_method,
				)
			);
			$authorize_url = add_query_arg( $authorize_params, self::get_endpoint_url( 'oauth/authorize' ) );
			wp_safe_redirect( wp_login_url( $authorize_url ) );
			exit;
		}

		/**
		 * Filters whether the current user may sign in to the client.
		 *
		 * Runs for every authorization request of a logged-in user (both when the
		 * consent screen is requested and when it is submitted), before a code is
		 * issued. Return false or a WP_Error to answer with error=access_denied.
		 *
		 * @param bool    $allowed   Whether sign-in is allowed.
		 * @param WP_User $user      Current user.
		 * @param string  $client_id Client ID.
		 * @param string  $scope     Granted scope string.
		 */
		$allowed = apply_filters( 'keystone_oidc_authorize_user', true, wp_get_current_user(), $client_id, $scope );
		if ( is_wp_error( $allowed ) || ! $allowed ) {
			$message = is_wp_error( $allowed ) ? $allowed->get_error_message() : 'Access denied.';
			$this->redirect_with_error( $redirect_uri, 'access_denied', $message, $state );
			return;
		}

		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$this->handle_authorize_post( $client_id, $redirect_uri, $scope, $state, $nonce, $code_challenge, $code_challenge_method );
			return;
		}

		$this->render_consent_page( $client, $scope, $state, $nonce, $redirect_uri, $code_challenge, $code_challenge_method );
	}

	private function handle_authorize_post( $client_id, $redirect_uri, $scope, $state, $nonce, $code_challenge, $code_challenge_method ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$nonce_value = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce_value, 'oidc_authorize' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'keystone-oidc' ) );
		}

		$user_id = get_current_user_id();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['authorize'] ) && 'deny' === sanitize_text_field( wp_unslash( $_POST['authorize'] ) ) ) {
			$this->redirect_with_error( $redirect_uri, 'access_denied', 'User denied authorization.', $state );
			return;
		}

		$code = KEYSTONE_OIDC_Token_Manager::generate_auth_code( $client_id, $user_id, $redirect_uri, $scope, $nonce, $code_challenge, $code_challenge_method );

		$params = array( 'code' => $code );
		if ( $state ) {
			$params['state'] = $state;
		}

		wp_redirect( add_query_arg( $params, $redirect_uri ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	private function render_consent_page( $client, $scope, $state, $nonce, $redirect_uri, $code_challenge, $code_challenge_method ) {
		$user             = wp_get_current_user();
		$scope_labels     = array(
			'openid'  => __( 'Verify your identity', 'keystone-oidc' ),
			'profile' => __( 'Access your name and username', 'keystone-oidc' ),
			'email'   => __( 'Access your email address', 'keystone-oidc' ),
			'roles'   => __( 'Access your WordPress roles', 'keystone-oidc' ),
		);
		$requested_scopes = explode( ' ', $scope );
		$authorize_url    = add_query_arg(
			array_filter(
				array(
					'response_type'         => 'code',
					'client_id'             => $client->client_id,
					'redirect_uri'          => $redirect_uri,
					'scope'                 => $scope,
					'state'                 => $state,
					'nonce'                 => $nonce,
					'code_challenge'        => $code_challenge,
					'code_challenge_method' => $code_challenge_method,
				)
			),
			self::get_endpoint_url( 'oauth/authorize' )
		);
		include KEYSTONE_OIDC_PLUGIN_DIR . 'includes/views/consent.php';
		exit;
	}

	// -------------------------------------------------------------------------
	// Token Endpoint
	// -------------------------------------------------------------------------

	private function handle_token() {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			$this->send_json_error( array( 'error' => 'invalid_request', 'error_description' => 'POST required.' ), 405 );
			return;
		}

		$client_id     = '';
		$client_secret = '';

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$body_client_id = isset( $_POST['client_id'] ) ? sanitize_text_field( wp_unslash( $_POST['client_id'] ) ) : '';

		$auth_header = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) ) : '';
		if ( $auth_header && 0 === strpos( $auth_header, 'Basic ' ) ) {
			$decoded = base64_decode( substr( $auth_header, 6 ), true );
			if ( false !== $decoded && strpos( $decoded, ':' ) !== false ) {
				list( $client_id, $client_secret ) = explode( ':', $decoded, 2 );
				// RFC 6749 §2.3.1: credentials are form-urlencoded before Base64.
				$client_id     = urldecode( $client_id );
				$client_secret = urldecode( $client_secret );
				if ( '' !== $body_client_id && $body_client_id !== $client_id ) {
					$this->send_json_error( array( 'error' => 'invalid_request', 'error_description' => 'client_id mismatch between Authorization header and body.' ), 400 );
					return;
				}
			}
		}

		if ( ! $client_id ) {
			$client_id     = $body_client_id;
			$client_secret = isset( $_POST['client_secret'] ) ? sanitize_text_field( wp_unslash( $_POST['client_secret'] ) ) : '';
		}

		$grant_type    = isset( $_POST['grant_type'] ) ? sanitize_text_field( wp_unslash( $_POST['grant_type'] ) ) : '';
		$code          = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$redirect_uri  = isset( $_POST['redirect_uri'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_uri'] ) ) : '';
		$refresh_token = isset( $_POST['refresh_token'] ) ? sanitize_text_field( wp_unslash( $_POST['refresh_token'] ) ) : '';
		$code_verifier = isset( $_POST['code_verifier'] ) ? sanitize_text_field( wp_unslash( $_POST['code_verifier'] ) ) : null;
		// phpcs:enable

		$client = KEYSTONE_OIDC_Client_Manager::get_client( $client_id );
		if ( ! $client ) {
			$this->send_json_error( array( 'error' => 'invalid_client', 'error_description' => 'Unknown client.' ), 401 );
			return;
		}

		// Confidential clients must always authenticate. Public clients have no
		// usable secret and are protected by PKCE instead (enforced on the code grant).
		$is_public = KEYSTONE_OIDC_Client_Manager::is_public( $client );
		if ( ! $is_public ) {
			if ( '' === (string) $client_secret || ! KEYSTONE_OIDC_Client_Manager::verify_secret( $client_secret, $client->client_secret ) ) {
				header( 'WWW-Authenticate: Basic realm="oidc", charset="UTF-8"' );
				$this->send_json_error( array( 'error' => 'invalid_client', 'error_description' => 'Client authentication failed.' ), 401 );
				return;
			}
		}

		switch ( $grant_type ) {
			case 'authorization_code':
				$this->handle_auth_code_grant( $client_id, $code, $redirect_uri, $code_verifier, $is_public );
				break;
			case 'refresh_token':
				$this->handle_refresh_token_grant( $client_id, $refresh_token );
				break;
			default:
				$this->send_json_error( array( 'error' => 'unsupported_grant_type' ), 400 );
		}
	}

	private function handle_auth_code_grant( $client_id, $code, $redirect_uri, $code_verifier, $require_pkce = false ) {
		$auth_code = KEYSTONE_OIDC_Token_Manager::consume_auth_code( $code, $client_id, $redirect_uri, $code_verifier, $require_pkce );
		if ( is_wp_error( $auth_code ) ) {
			$this->send_json_error( array( 'error' => $auth_code->get_error_code(), 'error_description' => $auth_code->get_error_message() ), 400 );
			return;
		}

		$tokens = KEYSTONE_OIDC_Token_Manager::issue_tokens( $client_id, $auth_code->user_id, $auth_code->scope, $auth_code->nonce );

		$this->send_json(
			array(
				'access_token'  => $tokens['access_token'],
				'token_type'    => 'Bearer',
				'expires_in'    => $tokens['expires_in'],
				'id_token'      => $tokens['id_token'],
				'refresh_token' => $tokens['refresh_token'],
				'scope'         => $auth_code->scope,
			)
		);
	}

	private function handle_refresh_token_grant( $client_id, $refresh_token ) {
		if ( ! $refresh_token ) {
			$this->send_json_error( array( 'error' => 'invalid_request', 'error_description' => 'refresh_token required.' ), 400 );
			return;
		}

		$tokens = KEYSTONE_OIDC_Token_Manager::refresh_tokens( $refresh_token, $client_id );
		if ( is_wp_error( $tokens ) ) {
			$this->send_json_error( array( 'error' => $tokens->get_error_code(), 'error_description' => $tokens->get_error_message() ), 400 );
			return;
		}

		$this->send_json(
			array(
				'access_token'  => $tokens['access_token'],
				'token_type'    => 'Bearer',
				'expires_in'    => $tokens['expires_in'],
				'id_token'      => $tokens['id_token'],
				'refresh_token' => $tokens['refresh_token'],
			)
		);
	}

	// -------------------------------------------------------------------------
	// UserInfo Endpoint
	// -------------------------------------------------------------------------

	private function handle_userinfo() {
		$access_token = '';

		$auth_header = isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) ) : '';
		if ( $auth_header && 0 === strpos( $auth_header, 'Bearer ' ) ) {
			$access_token = substr( $auth_header, 7 );
		}

		if ( ! $access_token ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$access_token = isset( $_GET['access_token'] ) ? sanitize_text_field( wp_unslash( $_GET['access_token'] ) ) : '';
		}

		if ( ! $access_token ) {
			header( 'WWW-Authenticate: Bearer realm="OIDC"' );
			$this->send_json_error( array( 'error' => 'invalid_token', 'error_description' => 'Bearer token required.' ), 401 );
			return;
		}

		$payload = KEYSTONE_OIDC_Token_Manager::validate_access_token( $access_token );
		if ( is_wp_error( $payload ) ) {
			header( 'WWW-Authenticate: Bearer error="' . esc_attr( $payload->get_error_code() ) . '"' );
			$this->send_json_error( array( 'error' => $payload->get_error_code(), 'error_description' => $payload->get_error_message() ), 401 );
			return;
		}

		$user_id = intval( $payload['sub'] );
		$scopes  = isset( $payload['scope'] ) ? explode( ' ', $payload['scope'] ) : array();
		$user    = get_userdata( $user_id );

		if ( ! $user ) {
			$this->send_json_error( array( 'error' => 'invalid_token', 'error_description' => 'User not found.' ), 401 );
			return;
		}

		$userinfo = array_merge(
			array( 'sub' => (string) $user_id ),
			KEYSTONE_OIDC_Token_Manager::build_user_claims( $user, $scopes )
		);
		$userinfo = KEYSTONE_OIDC_Token_Manager::apply_claims_filter( 'keystone_oidc_userinfo_claims', $userinfo, $user, isset( $payload['aud'] ) ? $payload['aud'] : '', $scopes );

		$this->send_json( $userinfo );
	}

	// -------------------------------------------------------------------------
	// JWKS Endpoint
	// -------------------------------------------------------------------------

	private function handle_jwks() {
		$this->send_json( KEYSTONE_OIDC_Token_Manager::get_jwks() );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	private function send_json( $data, $status = 200 ) {
		status_header( $status );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Cache-Control: no-store' );
		header( 'Pragma: no-cache' );
		echo wp_json_encode( $data );
		exit;
	}

	private function send_json_error( $data, $status = 400 ) {
		$this->send_json( $data, $status );
	}

	private function redirect_with_error( $redirect_uri, $error, $description, $state ) {
		if ( ! $redirect_uri ) {
			$this->send_json_error( array( 'error' => $error, 'error_description' => $description ), 400 );
			return;
		}
		$params = array(
			'error'             => $error,
			'error_description' => $description,
		);
		if ( $state ) {
			$params['state'] = $state;
		}
		wp_redirect( add_query_arg( $params, $redirect_uri ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}
}

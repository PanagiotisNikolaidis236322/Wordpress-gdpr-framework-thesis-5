<?php
namespace GDPRFramework\Components;

/**
 * API Security Manager
 * 
 * Implements security measures for API access as specified in Appendix A
 * - OAuth 2.0 Authentication
 * - JWT-Based Session Handling
 * - Rate Limiting
 * - IP Whitelisting
 * - TLS 1.3 Enforcement
 * - Two-Factor Authentication support
 */
class APISecurity {
    private $settings;
    private $db;
    private $jwt_secret;
    private $min_tls_version = '1.3'; // Minimum required TLS version
    private $rate_limits = [
        'default' => [
            'requests' => 60,    // Requests per period
            'period' => 60       // Period in seconds (1 minute)
        ],
        'high' => [
            'requests' => 300,   // Higher limit for admin operations
            'period' => 60
        ]
    ];
    
    public function __construct($database, $settings) {
        $this->db = $database;
        $this->settings = $settings;
        
        // Initialize JWT secret (using encryption key or generate new one)
        $this->initializeJWTSecret();
        
        // Register hooks
        add_action('rest_api_init', [$this, 'registerRoutes']);
        add_filter('rest_pre_dispatch', [$this, 'enforceTLSVersion'], 10, 3);
        add_filter('rest_authentication_errors', [$this, 'validateAPIRequest']);
        add_action('admin_init', [$this, 'registerSettings']);
    }
    
    /**
     * Initialize JWT Secret
     */
    private function initializeJWTSecret() {
        $jwt_secret = get_option('gdpr_jwt_secret');
        
        if (!$jwt_secret) {
            // Generate a secure random key for JWT
            if (function_exists('random_bytes')) {
                $jwt_secret = bin2hex(random_bytes(32));
            } else if (function_exists('openssl_random_pseudo_bytes')) {
                $jwt_secret = bin2hex(openssl_random_pseudo_bytes(32));
            } else {
                // Less secure fallback
                $jwt_secret = md5(uniqid(mt_rand(), true)) . md5(uniqid(mt_rand(), true));
            }
            
            update_option('gdpr_jwt_secret', $jwt_secret);
        }
        
        $this->jwt_secret = $jwt_secret;
    }
    
    /**
     * Register settings for API security
     */
    public function registerSettings() {
        register_setting('gdpr_framework_settings', 'gdpr_api_enabled', [
            'type' => 'boolean',
            'default' => 0,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_api_whitelist', [
            'type' => 'string',
            'default' => '',
            'sanitize_callback' => [$this, 'sanitizeIPWhitelist']
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_api_require_2fa', [
            'type' => 'boolean',
            'default' => 1,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_api_rate_limit', [
            'type' => 'integer',
            'default' => 60,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_api_enforce_tls', [
            'type' => 'boolean',
            'default' => 1,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_api_token_expiry', [
            'type' => 'integer',
            'default' => 3600, // 1 hour default
            'sanitize_callback' => 'absint'
        ]);
        
        // Register settings section and fields
        add_settings_section(
            'gdpr_api_security_section',
            __('API Security Settings', 'wp-gdpr-framework'),
            [$this, 'renderAPISectionDescription'],
            'gdpr_framework_settings'
        );
        
        add_settings_field(
            'gdpr_api_enabled',
            __('Enable API Access', 'wp-gdpr-framework'),
            [$this, 'renderAPIEnabledField'],
            'gdpr_framework_settings',
            'gdpr_api_security_section'
        );
        
        add_settings_field(
            'gdpr_api_whitelist',
            __('IP Whitelist', 'wp-gdpr-framework'),
            [$this, 'renderIPWhitelistField'],
            'gdpr_framework_settings',
            'gdpr_api_security_section'
        );
        
        add_settings_field(
            'gdpr_api_require_2fa',
            __('Require Two-Factor Authentication', 'wp-gdpr-framework'),
            [$this, 'renderRequire2FAField'],
            'gdpr_framework_settings',
            'gdpr_api_security_section'
        );
        
        add_settings_field(
            'gdpr_api_rate_limit',
            __('Rate Limiting', 'wp-gdpr-framework'),
            [$this, 'renderRateLimitField'],
            'gdpr_framework_settings',
            'gdpr_api_security_section'
        );
        
        add_settings_field(
            'gdpr_api_enforce_tls',
            __('Enforce TLS 1.3', 'wp-gdpr-framework'),
            [$this, 'renderEnforceTLSField'],
            'gdpr_framework_settings',
            'gdpr_api_security_section'
        );
        
        add_settings_field(
            'gdpr_api_token_expiry',
            __('Token Expiration', 'wp-gdpr-framework'),
            [$this, 'renderTokenExpiryField'],
            'gdpr_framework_settings',
            'gdpr_api_security_section'
        );
    }
    
    /**
     * Render API Security section description
     */
    public function renderAPISectionDescription() {
        echo '<p>' . esc_html__('Configure security settings for the GDPR API access.', 'wp-gdpr-framework') . '</p>';
    }
    
    /**
     * Render API Enabled field
     */
    public function renderAPIEnabledField() {
        $enabled = get_option('gdpr_api_enabled', 0);
        
        echo '<input type="checkbox" id="gdpr_api_enabled" name="gdpr_api_enabled" value="1" ' . 
             checked($enabled, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Enable API access for third-party applications.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render IP Whitelist field
     */
    public function renderIPWhitelistField() {
        $whitelist = get_option('gdpr_api_whitelist', '');
        
        echo '<textarea id="gdpr_api_whitelist" name="gdpr_api_whitelist" rows="3" cols="40" class="regular-text">' . 
             esc_textarea($whitelist) . '</textarea>';
             
        echo '<p class="description">' . 
             esc_html__('Enter IP addresses to whitelist (one per line). Empty means all IPs are allowed.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render Require 2FA field
     */
    public function renderRequire2FAField() {
        $require_2fa = get_option('gdpr_api_require_2fa', 1);
        
        echo '<input type="checkbox" id="gdpr_api_require_2fa" name="gdpr_api_require_2fa" value="1" ' . 
             checked($require_2fa, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Require two-factor authentication for API access.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render Rate Limit field
     */
    public function renderRateLimitField() {
        $rate_limit = get_option('gdpr_api_rate_limit', 60);
        
        echo '<input type="number" id="gdpr_api_rate_limit" name="gdpr_api_rate_limit" value="' . 
             esc_attr($rate_limit) . '" min="10" max="600" step="1" class="small-text"> ' . 
             esc_html__('requests per minute', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('Maximum number of API requests allowed per minute per IP address.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render Enforce TLS field
     */
    public function renderEnforceTLSField() {
        $enforce_tls = get_option('gdpr_api_enforce_tls', 1);
        
        echo '<input type="checkbox" id="gdpr_api_enforce_tls" name="gdpr_api_enforce_tls" value="1" ' . 
             checked($enforce_tls, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Require TLS 1.3 or higher for API connections to ensure secure data transmission.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render Token Expiry field
     */
    public function renderTokenExpiryField() {
        $token_expiry = get_option('gdpr_api_token_expiry', 3600);
        
        echo '<input type="number" id="gdpr_api_token_expiry" name="gdpr_api_token_expiry" value="' . 
             esc_attr($token_expiry) . '" min="300" max="86400" step="300" class="regular-text"> ' . 
             esc_html__('seconds', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('Time in seconds before an access token expires. Default: 1 hour (3600 seconds).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Sanitize IP Whitelist input
     */
    public function sanitizeIPWhitelist($input) {
        $ips = explode("\n", $input);
        $valid_ips = [];
        
        foreach ($ips as $ip) {
            $ip = trim($ip);
            
            if (empty($ip)) {
                continue;
            }
            
            // Validate IPv4 or IPv6 address
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid_ips[] = $ip;
            }
            
            // Validate CIDR notation
            if (strpos($ip, '/') !== false) {
                list($subnet, $bits) = explode('/', $ip);
                if (filter_var($subnet, FILTER_VALIDATE_IP) && is_numeric($bits)) {
                    $valid_ips[] = $ip;
                }
            }
        }
        
        return implode("\n", $valid_ips);
    }
    
    /**
     * Register REST API routes
     */
    public function registerRoutes() {
        register_rest_route('gdpr/v1', '/auth', [
            'methods' => 'POST',
            'callback' => [$this, 'handleAuth'],
            'permission_callback' => '__return_true'
        ]);
        
        register_rest_route('gdpr/v1', '/refresh', [
            'methods' => 'POST',
            'callback' => [$this, 'handleRefreshToken'],
            'permission_callback' => '__return_true'
        ]);
        
        register_rest_route('gdpr/v1', '/verify', [
            'methods' => 'POST',
            'callback' => [$this, 'handle2FAVerification'],
            'permission_callback' => '__return_true'
        ]);
        
        // Data endpoints - these require authentication
        register_rest_route('gdpr/v1', '/consents', [
            'methods' => 'GET',
            'callback' => [$this, 'handleGetConsents'],
            'permission_callback' => [$this, 'checkAPIPermission']
        ]);
        
        register_rest_route('gdpr/v1', '/consents', [
            'methods' => 'POST',
            'callback' => [$this, 'handleUpdateConsent'],
            'permission_callback' => [$this, 'checkAPIPermission']
        ]);
        
        register_rest_route('gdpr/v1', '/data-requests', [
            'methods' => 'GET',
            'callback' => [$this, 'handleGetDataRequests'],
            'permission_callback' => [$this, 'checkAPIPermission']
        ]);
        
        register_rest_route('gdpr/v1', '/data-requests', [
            'methods' => 'POST',
            'callback' => [$this, 'handleCreateDataRequest'],
            'permission_callback' => [$this, 'checkAPIPermission']
        ]);
    }
    
    /**
     * Enforce TLS version for API requests
     */
    public function enforceTLSVersion($result, $server, $request) {
        // Only enforce for GDPR API endpoints
        if (strpos($request->get_route(), '/gdpr/v1') !== 0) {
            return $result;
        }
        
        // Check if TLS enforcement is enabled
        $enforce_tls = get_option('gdpr_api_enforce_tls', 1);
        if (!$enforce_tls) {
            return $result;
        }
        
        // Check for HTTPS
        if (!is_ssl()) {
            return new \WP_Error(
                'insecure_connection',
                __('GDPR API requires a secure HTTPS connection.', 'wp-gdpr-framework'),
                ['status' => 403]
            );
        }
        
        // Attempt to detect TLS version
        $tls_version = $this->detectTLSVersion();
        
        // If we can't detect the TLS version but require it, we should log a warning
        if ($tls_version === 'unknown') {
            error_log('GDPR Framework - Warning: Unable to detect TLS version for API request. Proceeding with caution.');
            return $result;
        }
        
        // Check if TLS version meets requirements
        if (version_compare($tls_version, $this->min_tls_version, '<')) {
            return new \WP_Error(
                'tls_version_too_low',
                sprintf(
                    __('GDPR API requires TLS %s or higher. Detected version: %s', 'wp-gdpr-framework'),
                    $this->min_tls_version,
                    $tls_version
                ),
                ['status' => 403]
            );
        }
        
        return $result;
    }
    
    /**
     * Detect TLS version
     */
    private function detectTLSVersion() {
        // This is a best-effort detection since PHP doesn't provide a reliable way to detect TLS version
        
        // Check for TLS 1.3 header (some servers/proxies might set this)
        $server_vars = ['SSL_PROTOCOL', 'HTTPS_PROTOCOL', 'TLS_VERSION', 'SERVER_PROTOCOL'];
        foreach ($server_vars as $var) {
            if (isset($_SERVER[$var]) && preg_match('/TLSv?([0-9.]+)/i', $_SERVER[$var], $matches)) {
                return $matches[1];
            }
        }
        
        // Check Cloudflare specific header
        if (isset($_SERVER['HTTP_CF_TLS_VERSION'])) {
            return $_SERVER['HTTP_CF_TLS_VERSION'];
        }
        
        // Check if OpenSSL information is available
        if (function_exists('openssl_get_cipher_methods')) {
            $ciphers = openssl_get_cipher_methods();
            
            // TLS 1.3 specific ciphers
            $tls13_ciphers = ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256'];
            
            foreach ($tls13_ciphers as $cipher) {
                if (in_array($cipher, $ciphers)) {
                    return '1.3'; // TLS 1.3 support is available
                }
            }
            
            // TLS 1.2 specific ciphers
            $tls12_ciphers = ['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES256-GCM-SHA384'];
            
            foreach ($tls12_ciphers as $cipher) {
                if (in_array($cipher, $ciphers)) {
                    return '1.2'; // TLS 1.2 support is available
                }
            }
        }
        
        // If we've made it this far and we're on HTTPS, assume at least TLS 1.0
        if (is_ssl()) {
            return '1.0';
        }
        
        return 'unknown';
    }
    
    /**
     * Handle authentication request
     */
    public function handleAuth($request) {
        $api_enabled = get_option('gdpr_api_enabled', 0);
        
        if (!$api_enabled) {
            return new \WP_Error(
                'api_disabled',
                __('API access is disabled.', 'wp-gdpr-framework'),
                ['status' => 403]
            );
        }
        
        // Check if IP is whitelisted
        if (!$this->isIPWhitelisted()) {
            return new \WP_Error(
                'ip_not_whitelisted',
                __('Access denied: Your IP address is not whitelisted.', 'wp-gdpr-framework'),
                ['status' => 403]
            );
        }
        
        // Check for rate limiting
        if ($this->isRateLimited('auth')) {
            return new \WP_Error(
                'rate_limited',
                __('Too many requests. Please try again later.', 'wp-gdpr-framework'),
                ['status' => 429]
            );
        }
        
        // Get credentials from request
        $username = $request->get_param('username');
        $password = $request->get_param('password');
        $client_id = $request->get_param('client_id');
        $client_secret = $request->get_param('client_secret');
        
        // Check if using client credentials or password grant
        if (!empty($client_id) && !empty($client_secret)) {
            // Client credentials grant
            $client = $this->validateClientCredentials($client_id, $client_secret);
            if (is_wp_error($client)) {
                return $client;
            }
            
            // Generate tokens for client
            $tokens = $this->generateClientTokens($client);
            
            // Log successful authentication
            do_action('gdpr_api_client_authenticated', $client_id);
            
            return $tokens;
        }
        
        // Password grant
        if (empty($username) || empty($password)) {
            return new \WP_Error(
                'missing_credentials',
                __('Username and password are required.', 'wp-gdpr-framework'),
                ['status' => 400]
            );
        }
        
        // Authenticate user
        $user = wp_authenticate($username, $password);
        
        if (is_wp_error($user)) {
            return new \WP_Error(
                'invalid_credentials',
                __('Invalid username or password.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Check for 2FA if required
        $require_2fa = get_option('gdpr_api_require_2fa', 1);
        
        if ($require_2fa) {
            // Check if user has MFA enabled
            $has_mfa = get_user_meta($user->ID, 'gdpr_mfa_enabled', true);
            
            if ($has_mfa) {
                // Return a challenge response for 2FA
                return [
                    'status' => 'mfa_required',
                    'user_id' => $user->ID,
                    'challenge_token' => $this->generateMFAChallengeToken($user->ID),
                    'message' => __('Two-factor authentication required.', 'wp-gdpr-framework')
                ];
            }
        }
        
        // Generate tokens for user
        $tokens = $this->generateUserTokens($user->ID);
        
        // Log successful authentication
        do_action('gdpr_api_authenticated', $user->ID);
        
        return $tokens;
    }
    
    /**
     * Handle 2FA verification
     */
    public function handle2FAVerification($request) {
        $challenge_token = $request->get_param('challenge_token');
        $code = $request->get_param('code');
        
        if (empty($challenge_token) || empty($code)) {
            return new \WP_Error(
                'missing_parameters',
                __('Challenge token and verification code are required.', 'wp-gdpr-framework'),
                ['status' => 400]
            );
        }
        
        // Validate challenge token
        $user_id = $this->validateMFAChallengeToken($challenge_token);
        
        if (!$user_id) {
            return new \WP_Error(
                'invalid_challenge',
                __('Invalid or expired challenge token.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Check if user has MFA enabled
        $secret = get_user_meta($user_id, 'gdpr_mfa_secret', true);
        
        if (empty($secret)) {
            return new \WP_Error(
                'mfa_not_enabled',
                __('Two-factor authentication not set up for this user.', 'wp-gdpr-framework'),
                ['status' => 400]
            );
        }
        
        // Verify code
        if (!$this->verify2FACode($user_id, $code)) {
            // Log failed attempt
            do_action('gdpr_mfa_failed', $user_id, [
                'ip_address' => $this->getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);
            
            return new \WP_Error(
                'invalid_code',
                __('Invalid verification code.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Generate tokens for user
        $tokens = $this->generateUserTokens($user_id);
        
        // Log successful authentication
        do_action('gdpr_api_authenticated', $user_id);
        
        return $tokens;
    }
    
    /**
     * Handle token refresh
     */
    public function handleRefreshToken($request) {
        $refresh_token = $request->get_param('refresh_token');
        
        if (empty($refresh_token)) {
            return new \WP_Error(
                'missing_token',
                __('Refresh token is required.', 'wp-gdpr-framework'),
                ['status' => 400]
            );
        }
        
        // Validate refresh token
        $payload = $this->validateRefreshToken($refresh_token);
        
        if (!$payload) {
            return new \WP_Error(
                'invalid_token',
                __('Invalid or expired refresh token.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Check if it's a user or client token
        if (isset($payload['data']['user_id'])) {
            // User token
            $user_id = $payload['data']['user_id'];
            $tokens = $this->generateUserTokens($user_id);
            
            // Log token refresh
            do_action('gdpr_api_token_refreshed', $user_id);
            
            return $tokens;
        } elseif (isset($payload['data']['client_id'])) {
            // Client token
            $client_id = $payload['data']['client_id'];
            $tokens = $this->generateClientTokens(['client_id' => $client_id]);
            
            // Log token refresh
            do_action('gdpr_api_token_refreshed', $client_id);
            
            return $tokens;
        }
        
        return new \WP_Error(
            'invalid_token',
            __('Invalid token format.', 'wp-gdpr-framework'),
            ['status' => 401]
        );
    }
    
    /**
     * Check if user has permission for API access
     */
    public function checkAPIPermission($request) {
        $auth_header = $request->get_header('authorization');
        
        if (!$auth_header || strpos($auth_header, 'Bearer ') !== 0) {
            return new \WP_Error(
                'missing_authorization',
                __('Authorization header missing or invalid.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Extract token
        $token = substr($auth_header, 7);
        
        // Validate token
        $payload = $this->validateJWT($token);
        
        if (!$payload) {
            return new \WP_Error(
                'invalid_token',
                __('Invalid or expired token.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Check if it's a user or client token
        if (isset($payload['data']['user_id'])) {
            // User token - set current user
            $user_id = $payload['data']['user_id'];
            wp_set_current_user($user_id);
            
            // Check if user exists
            $user = get_user_by('id', $user_id);
            if (!$user) {
                return new \WP_Error(
                    'user_not_found',
                    __('User no longer exists.', 'wp-gdpr-framework'),
                    ['status' => 401]
                );
            }
            
            return true;
        } elseif (isset($payload['data']['client_id'])) {
            // Client token - check client permissions
            $client_id = $payload['data']['client_id'];
            
            // Set the client ID in request data for later use
            $request->set_param('_gdpr_client_id', $client_id);
            
            return true;
        }
        
        return new \WP_Error(
            'invalid_token',
            __('Invalid token format.', 'wp-gdpr-framework'),
            ['status' => 401]
        );
    }
    
    /**
     * Validate client credentials
     */
    private function validateClientCredentials($client_id, $client_secret) {
        // Get registered clients
        $clients = get_option('gdpr_api_clients', []);
        
        if (!isset($clients[$client_id])) {
            return new \WP_Error(
                'client_not_found',
                __('Client not found.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        $client = $clients[$client_id];
        
        // Verify client secret using constant-time comparison
        if (!hash_equals($client['secret'], $client_secret)) {
            return new \WP_Error(
                'invalid_client_secret',
                __('Invalid client secret.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        return $client;
    }
    
    /**
     * Verify 2FA code for a user
     */
    private function verify2FACode($user_id, $code) {
        // Get MFA secret for user
        $secret = get_user_meta($user_id, 'gdpr_mfa_secret', true);
        
        if (empty($secret)) {
            return false;
        }
        
        // Check if we have the MultiFactorAuthManager component available
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
        $mfa_manager = $framework->getComponent('mfa');
        
        if ($mfa_manager && method_exists($mfa_manager, 'verifyTOTPCode')) {
            // Use the MFA manager to verify the code
            return $mfa_manager->verifyTOTPCode($secret, $code);
        }
        
        // Fallback verification implementation
        return $this->verifyTOTPCode($secret, $code);
    }
    
    /**
     * Verify a TOTP code (fallback implementation)
     */
    private function verifyTOTPCode($secret, $code, $window = 1) {
        if (empty($secret) || empty($code) || !is_numeric($code) || strlen($code) !== 6) {
            return false;
        }
        
        // Simple verification for demonstration
        // In a real implementation, you would use a proper TOTP library
        
        // Get current time window
        $timestamp = floor(time() / 30);
        
        // Check codes in the time window
        for ($i = -$window; $i <= $window; $i++) {
            $expectedCode = $this->generateTOTPCode($secret, $timestamp + $i);
            
            if ($expectedCode === $code) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate a TOTP code (fallback implementation)
     */
    private function generateTOTPCode($secret, $timestamp) {
        // This is a simplified implementation
        // In a real application, use a proper TOTP library
        
        // Convert secret from base32 to binary
        $secretKey = $this->base32Decode($secret);
        
        // Pack timestamp as big-endian 64-bit value
        $time = pack('N*', 0, $timestamp);
        
        // Generate HMAC-SHA1 hash
        $hash = hash_hmac('sha1', $time, $secretKey, true);
        
        // Get offset based on last nibble of hash
        $offset = ord($hash[19]) & 0x0F;
        
        // Get 4 bytes starting at offset
        $code = ((ord($hash[$offset]) & 0x7F) << 24) |
                ((ord($hash[$offset + 1]) & 0xFF) << 16) |
                ((ord($hash[$offset + 2]) & 0xFF) << 8) |
                (ord($hash[$offset + 3]) & 0xFF);
        
        // Take modulo to get a 6-digit code
        $code = $code % 1000000;
        
        // Ensure 6 digits with leading zeros
        return str_pad($code, 6, '0', STR_PAD_LEFT);
    }
    
    /**
     * Base32 decode function
     */
    private function base32Decode($input) {
        $map = [
            'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, 'E' => 4, 'F' => 5, 'G' => 6, 'H' => 7,
            'I' => 8, 'J' => 9, 'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15,
            'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23,
            'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29, '6' => 30, '7' => 31
        ];
        
        $input = strtoupper($input);
        $output = '';
        $buffer = 0;
        $bits = 0;
        
        for ($i = 0; $i < strlen($input); $i++) {
            $char = $input[$i];
            
            if (!isset($map[$char])) {
                continue;
            }
            
            $buffer = ($buffer << 5) | $map[$char];
            $bits += 5;
            
            if ($bits >= 8) {
                $bits -= 8;
                $output .= chr(($buffer >> $bits) & 0xFF);
                $buffer &= (1 << $bits) - 1;
            }
        }
        
        return $output;
    }
    
    /**
     * Generate MFA challenge token
     */
    private function generateMFAChallengeToken($user_id) {
        $token_data = [
            'user_id' => $user_id,
            'exp' => time() + 300 // 5 minutes expiry
        ];
        
        return $this->generateJWT($token_data, 'mfa_challenge');
    }
    
    /**
     * Validate MFA challenge token
     */
    private function validateMFAChallengeToken($token) {
        $payload = $this->validateJWT($token);
        
        if (!$payload || !isset($payload['type']) || $payload['type'] !== 'mfa_challenge' || !isset($payload['data']['user_id'])) {
            return false;
        }
        
        return $payload['data']['user_id'];
    }
    
    /**
     * Generate tokens for user
     */
    private function generateUserTokens($user_id) {
        $token_expiry = get_option('gdpr_api_token_expiry', 3600);
        $refresh_expiry = $token_expiry * 24; // 24 times longer than access token
        
        // Generate access token
        $access_token = $this->generateJWT([
            'user_id' => $user_id,
            'exp' => time() + $token_expiry
        ]);
        
        // Generate refresh token with longer expiry
        $refresh_token = $this->generateJWT([
            'user_id' => $user_id,
            'exp' => time() + $refresh_expiry
        ], 'refresh');
        
        return [
            'access_token' => $access_token,
            'token_type' => 'Bearer',
            'expires_in' => $token_expiry,
            'refresh_token' => $refresh_token,
            'user_id' => $user_id
        ];
    }
    
    /**
     * Generate tokens for client
     */
    private function generateClientTokens($client) {
        $token_expiry = get_option('gdpr_api_token_expiry', 3600);
        $refresh_expiry = $token_expiry * 24; // 24 times longer than access token
        
        // Generate access token
        $access_token = $this->generateJWT([
            'client_id' => $client['client_id'],
            'exp' => time() + $token_expiry
        ]);
        
        // Generate refresh token with longer expiry
        $refresh_token = $this->generateJWT([
            'client_id' => $client['client_id'],
            'exp' => time() + $refresh_expiry
        ], 'refresh');
        
        return [
            'access_token' => $access_token,
            'token_type' => 'Bearer',
            'expires_in' => $token_expiry,
            'refresh_token' => $refresh_token,
            'client_id' => $client['client_id']
        ];
    }
    
    /**
     * Generate JWT token
     */
    private function generateJWT($data, $type = 'access') {
        $issued_at = time();
        
        $token = [
            'iss' => get_site_url(), // Issuer
            'iat' => $issued_at,     // Issued At
            'nbf' => $issued_at,     // Not Before
            'exp' => isset($data['exp']) ? $data['exp'] : ($issued_at + 3600),
            'type' => $type,
            'data' => $data
        ];
        
        // Remove exp from data if it's already in the token header
        if (isset($data['exp'])) {
            unset($token['data']['exp']);
        }
        
        // Generate JWT token
        $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
        $payload = base64_encode(json_encode($token));
        $signature = hash_hmac('sha256', "$header.$payload", $this->jwt_secret, true);
        $signature = base64_encode($signature);
        
        return "$header.$payload.$signature";
    }
    
    /**
     * Validate JWT token
     */
    private function validateJWT($token) {
        if (empty($token)) {
            return false;
        }
        
        $parts = explode('.', $token);
        
        if (count($parts) !== 3) {
            return false;
        }
        
        list($header, $payload, $signature) = $parts;
        
        // Verify signature
        $valid_signature = hash_hmac('sha256', "$header.$payload", $this->jwt_secret, true);
        $valid_signature = base64_encode($valid_signature);
        
        if (!hash_equals($signature, $valid_signature)) {
            return false;
        }
        
        // Decode payload
        $payload = json_decode(base64_decode($payload), true);
        
        // Check expiration
        if (!isset($payload['exp']) || $payload['exp'] < time()) {
            return false;
        }
        
        return $payload;
    }
    
    /**
     * Validate refresh token
     */
    private function validateRefreshToken($token) {
        $payload = $this->validateJWT($token);
        
        if (!$payload || !isset($payload['type']) || $payload['type'] !== 'refresh') {
            return false;
        }
        
        return $payload;
    }
    
    /**
     * Check if IP is whitelisted
     */
    private function isIPWhitelisted() {
        $whitelist = get_option('gdpr_api_whitelist', '');
        
        // If whitelist is empty, all IPs are allowed
        if (empty($whitelist)) {
            return true;
        }
        
        $ip = $this->getClientIP();
        $whitelist_ips = explode("\n", $whitelist);
        
        foreach ($whitelist_ips as $whitelisted_ip) {
            $whitelisted_ip = trim($whitelisted_ip);
            
            if (empty($whitelisted_ip)) {
                continue;
            }
            
            // Direct IP match
            if ($ip === $whitelisted_ip) {
                return true;
            }
            
            // CIDR notation support
            if (strpos($whitelisted_ip, '/') !== false) {
                if ($this->ipInCIDRRange($ip, $whitelisted_ip)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if IP is in CIDR range
     */
    private function ipInCIDRRange($ip, $cidr) {
        list($subnet, $bits) = explode('/', $cidr);
        
        $ip_binary = $this->ipToBinary($ip);
        $subnet_binary = $this->ipToBinary($subnet);
        
        $bits = (int) $bits;
        
        return substr($ip_binary, 0, $bits) === substr($subnet_binary, 0, $bits);
    }
    
    /**
     * Convert IP to binary representation
     */
    private function ipToBinary($ip) {
        $binary = '';
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4
            $parts = explode('.', $ip);
            foreach ($parts as $part) {
                $binary .= str_pad(decbin($part), 8, '0', STR_PAD_LEFT);
            }
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6
            $parts = explode(':', $ip);
            foreach ($parts as $part) {
                $binary .= str_pad(base_convert($part, 16, 2), 16, '0', STR_PAD_LEFT);
            }
        }
        
        return $binary;
    }
    
    /**
     * Check if request is rate limited
     */
    private function isRateLimited($endpoint = 'default') {
        $rate_limit = get_option('gdpr_api_rate_limit', 60);
        $ip = $this->getClientIP();
        $cache_key = 'gdpr_rate_limit_' . md5($ip . '_' . $endpoint);
        
        // Use transient for tracking requests
        $requests = get_transient($cache_key);
        
        if (false === $requests) {
            $requests = 0;
        }
        
        $requests++;
        
        // Store for 1 minute
        set_transient($cache_key, $requests, 60);
        
        return $requests > $rate_limit;
    }
    
    /**
     * Get client IP address with proper handling for proxies
     */
    private function getClientIP() {
        $ip = '';
        
        // Check for various proxy headers
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // HTTP_X_FORWARDED_FOR can contain multiple IPs, take the first one
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED'])) {
            $ip = $_SERVER['HTTP_FORWARDED'];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        // Validate the IP and return a default if it's invalid
        return filter_var($ip, FILTER_VALIDATE_IP) ?: '0.0.0.0';
    }
    
    /**
     * Handle getting consents for a user
     */
    public function handleGetConsents($request) {
        $user_id = get_current_user_id();
        
        // Check if it's a client request
        $client_id = $request->get_param('_gdpr_client_id');
        if ($client_id) {
            // Clients can only access user data if they provide a user ID
            $requested_user_id = $request->get_param('user_id');
            if (empty($requested_user_id)) {
                return new \WP_Error(
                    'missing_user_id',
                    __('User ID is required for client requests.', 'wp-gdpr-framework'),
                    ['status' => 400]
                );
            }
            
            // Verify the user exists
            $user = get_user_by('id', $requested_user_id);
            if (!$user) {
                return new \WP_Error(
                    'user_not_found',
                    __('User not found.', 'wp-gdpr-framework'),
                    ['status' => 404]
                );
            }
            
            $user_id = $requested_user_id;
        }
        
        // Get consent types
        $consent_types = get_option('gdpr_consent_types', []);
        
        // Get user consents
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
        $consent_manager = $framework->getComponent('consent');
        
        $user_consents = [];
        
        if ($consent_manager && method_exists($consent_manager, 'getConsentHistory')) {
            // Get detailed consent history
            $consent_history = $consent_manager->getConsentHistory($user_id);
            
            // Get current consent statuses
            foreach ($consent_types as $type_key => $type) {
                $status = false;
                
                if (method_exists($consent_manager, 'getConsentStatus')) {
                    $status = $consent_manager->getConsentStatus($type_key, $user_id);
                }
                
                $user_consents[$type_key] = [
                    'label' => $type['label'] ?? $type_key,
                    'status' => $status,
                    'required' => !empty($type['required']),
                    'description' => $type['description'] ?? ''
                ];
            }
            
            return [
                'user_id' => $user_id,
                'consents' => $user_consents,
                'history' => $consent_history
            ];
        }
        
        // Fallback if consent manager not available
        return [
            'user_id' => $user_id,
            'consents' => [],
            'error' => 'Consent manager not available'
        ];
    }
    
    /**
     * Handle updating consent for a user
     */
    public function handleUpdateConsent($request) {
        $user_id = get_current_user_id();
        
        // Check if it's a client request
        $client_id = $request->get_param('_gdpr_client_id');
        if ($client_id) {
            // Clients can only update user data if they provide a user ID
            $requested_user_id = $request->get_param('user_id');
            if (empty($requested_user_id)) {
                return new \WP_Error(
                    'missing_user_id',
                    __('User ID is required for client requests.', 'wp-gdpr-framework'),
                    ['status' => 400]
                );
            }
            
            // Verify the user exists
            $user = get_user_by('id', $requested_user_id);
            if (!$user) {
                return new \WP_Error(
                    'user_not_found',
                    __('User not found.', 'wp-gdpr-framework'),
                    ['status' => 404]
                );
            }
            
            $user_id = $requested_user_id;
        }
        
        // Get consent data from request
        $consents = $request->get_param('consents');
        
        if (!is_array($consents)) {
            return new \WP_Error(
                'invalid_consents',
                __('Consents must be provided as an object.', 'wp-gdpr-framework'),
                ['status' => 400]
            );
        }
        
        // Get consent types
        $consent_types = get_option('gdpr_consent_types', []);
        
        // Get consent manager
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
        $consent_manager = $framework->getComponent('consent');
        
        if (!$consent_manager || !method_exists($consent_manager, 'saveConsent')) {
            return new \WP_Error(
                'consent_manager_unavailable',
                __('Consent manager not available.', 'wp-gdpr-framework'),
                ['status' => 500]
            );
        }
        
        $updated_consents = [];
        
        // Process each consent
        foreach ($consents as $type_key => $status) {
            // Verify the consent type exists
            if (!isset($consent_types[$type_key])) {
                continue;
            }
            
            // Don't allow changing required consents to false
            if (!empty($consent_types[$type_key]['required']) && !$status) {
                continue;
            }
            
            // Save the consent
            $result = $consent_manager->saveConsent($user_id, $type_key, (bool)$status);
            
            if ($result) {
                $updated_consents[$type_key] = [
                    'status' => (bool)$status,
                    'updated' => true
                ];
                
                // Trigger consent update action
                do_action('gdpr_consent_updated', $user_id, $type_key, (bool)$status);
            } else {
                $updated_consents[$type_key] = [
                    'status' => null,
                    'updated' => false,
                    'error' => 'Failed to update consent'
                ];
            }
        }
        
        return [
            'user_id' => $user_id,
            'updated_consents' => $updated_consents
        ];
    }
    
    /**
     * Handle getting data requests for a user
     */
    public function handleGetDataRequests($request) {
        $user_id = get_current_user_id();
        
        // Check if it's a client request
        $client_id = $request->get_param('_gdpr_client_id');
        if ($client_id) {
            // For clients, allow an admin to view all requests
            $view_all = $request->get_param('view_all');
            
            if ($view_all) {
                // Get portability manager
                $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
                $portability_manager = $framework->getComponent('portability');
                
                if (!$portability_manager || !method_exists($portability_manager, 'getRequestsWithUsers')) {
                    return new \WP_Error(
                        'portability_manager_unavailable',
                        __('Data portability manager not available.', 'wp-gdpr-framework'),
                        ['status' => 500]
                    );
                }
                
                return [
                    'requests' => $portability_manager->getRequestsWithUsers()
                ];
            }
            
            // Otherwise, clients need a user ID
            $requested_user_id = $request->get_param('user_id');
            if (empty($requested_user_id)) {
                return new \WP_Error(
                    'missing_user_id',
                    __('User ID is required for client requests.', 'wp-gdpr-framework'),
                    ['status' => 400]
                );
            }
            
            // Verify the user exists
            $user = get_user_by('id', $requested_user_id);
            if (!$user) {
                return new \WP_Error(
                    'user_not_found',
                    __('User not found.', 'wp-gdpr-framework'),
                    ['status' => 404]
                );
            }
            
            $user_id = $requested_user_id;
        }
        
        // Get portability manager
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
        $portability_manager = $framework->getComponent('portability');
        
        if (!$portability_manager) {
            return new \WP_Error(
                'portability_manager_unavailable',
                __('Data portability manager not available.', 'wp-gdpr-framework'),
                ['status' => 500]
            );
        }
        
        // Get user's data requests
        if (method_exists($portability_manager, 'getUserRequests')) {
            return [
                'user_id' => $user_id,
                'requests' => $portability_manager->getUserRequests($user_id)
            ];
        }
        
        return new \WP_Error(
            'method_not_available',
            __('Method not available.', 'wp-gdpr-framework'),
            ['status' => 500]
        );
    }
    
    /**
     * Handle creating a data request
     */
    public function handleCreateDataRequest($request) {
        $user_id = get_current_user_id();
        
        // Check if it's a client request
        $client_id = $request->get_param('_gdpr_client_id');
        if ($client_id) {
            // Clients can only create requests if they provide a user ID
            $requested_user_id = $request->get_param('user_id');
            if (empty($requested_user_id)) {
                return new \WP_Error(
                    'missing_user_id',
                    __('User ID is required for client requests.', 'wp-gdpr-framework'),
                    ['status' => 400]
                );
            }
            
            // Verify the user exists
            $user = get_user_by('id', $requested_user_id);
            if (!$user) {
                return new \WP_Error(
                    'user_not_found',
                    __('User not found.', 'wp-gdpr-framework'),
                    ['status' => 404]
                );
            }
            
            $user_id = $requested_user_id;
        }
        
        // Get request type
        $type = $request->get_param('type');
        
        if (!in_array($type, ['export', 'erasure'])) {
            return new \WP_Error(
                'invalid_request_type',
                __('Invalid request type. Must be "export" or "erasure".', 'wp-gdpr-framework'),
                ['status' => 400]
            );
        }
        
        // Get portability manager
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
        $portability_manager = $framework->getComponent('portability');
        
        if (!$portability_manager || !method_exists($portability_manager, 'createDataRequest')) {
            return new \WP_Error(
                'portability_manager_unavailable',
                __('Data portability manager not available.', 'wp-gdpr-framework'),
                ['status' => 500]
            );
        }
        
        try {
            $request_id = $portability_manager->createDataRequest($user_id, $type);
            
            // For API requests, automatically process the request if appropriate
            $auto_process = $request->get_param('auto_process');
            if ($auto_process && $request_id) {
                if ($type === 'export' && method_exists($portability_manager, 'processExportRequest')) {
                    $portability_manager->processExportRequest($request_id);
                } elseif ($type === 'erasure' && method_exists($portability_manager, 'processErasureRequest')) {
                    $portability_manager->processErasureRequest($request_id);
                }
            }
            
            return [
                'user_id' => $user_id,
                'request_id' => $request_id,
                'request_type' => $type,
                'status' => 'pending',
                'created_at' => current_time('mysql')
            ];
        } catch (\Exception $e) {
            return new \WP_Error(
                'request_creation_failed',
                $e->getMessage(),
                ['status' => 500]
            );
        }
    }
    
    /**
     * Validate API request authentication
     */
    public function validateAPIRequest($result) {
        // If already authenticated or not a REST request, return
        if ($result !== null || !defined('REST_REQUEST')) {
            return $result;
        }
        
        // Skip authentication for certain endpoints like auth
        $rest_route = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field($_SERVER['REQUEST_URI']) : '';
        
        if (strpos($rest_route, '/gdpr/v1/auth') !== false || 
            strpos($rest_route, '/gdpr/v1/refresh') !== false ||
            strpos($rest_route, '/gdpr/v1/verify') !== false) {
            return $result;
        }
        
        // Check if API is enabled
        $api_enabled = get_option('gdpr_api_enabled', 0);
        
        if (!$api_enabled) {
            return new \WP_Error(
                'api_disabled',
                __('API access is disabled.', 'wp-gdpr-framework'),
                ['status' => 403]
            );
        }
        
        // Check if IP is whitelisted
        if (!$this->isIPWhitelisted()) {
            return new \WP_Error(
                'ip_not_whitelisted',
                __('Access denied: Your IP address is not whitelisted.', 'wp-gdpr-framework'),
                ['status' => 403]
            );
        }
        
        // Check authorization header
        $auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? sanitize_text_field($_SERVER['HTTP_AUTHORIZATION']) : '';
        
        if (empty($auth_header) || strpos($auth_header, 'Bearer ') !== 0) {
            return new \WP_Error(
                'missing_authorization',
                __('Authorization header missing or invalid.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Extract token
        $token = substr($auth_header, 7);
        
        // Validate token
        $payload = $this->validateJWT($token);
        
        if (!$payload) {
            return new \WP_Error(
                'invalid_token',
                __('Invalid or expired token.', 'wp-gdpr-framework'),
                ['status' => 401]
            );
        }
        
        // Check if it's a user token
        if (isset($payload['data']['user_id'])) {
            // Set current user
            $user_id = $payload['data']['user_id'];
            wp_set_current_user($user_id);
        }
        
        return $result;
    }
}
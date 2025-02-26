<?php
namespace GDPRFramework\Components;

/**
 * Multi-Factor Authentication Manager
 * 
 * Implements Two-Factor Authentication capabilities as specified in Appendix A
 * - Time-Based One-Time Password (TOTP) support
 * - Device-based authentication
 * - IP-based restrictions
 */
class MultiFactorAuthManager {
    private $db;
    private $settings;
    private $secret_length = 16;
    private $table_name;

    public function __construct($database, $settings) {
        global $wpdb;
        $this->db = $database;
        $this->settings = $settings;
        $this->table_name = $wpdb->prefix . 'gdpr_mfa_devices';
        
        // Initialize hooks
        $this->initializeHooks();
        
        // Create tables if they don't exist
        $this->createTables();
    }
    
    /**
     * Initialize hooks for MFA
     */
    private function initializeHooks() {
        // Admin settings hooks
        add_action('admin_init', [$this, 'registerSettings']);
        
        // Authentication and setup hooks
        add_action('wp_login', [$this, 'checkMFARequirements'], 10, 2);
        add_action('admin_post_gdpr_setup_mfa', [$this, 'handleMFASetup']);
        add_action('admin_post_gdpr_verify_mfa', [$this, 'handleMFAVerification']);
        add_action('admin_post_gdpr_reset_mfa', [$this, 'handleMFAReset']);
        
        // AJAX handlers
        add_action('wp_ajax_gdpr_verify_mfa_code', [$this, 'ajaxVerifyCode']);
        add_action('wp_ajax_gdpr_trust_device', [$this, 'ajaxTrustDevice']);
        
        // User profile hooks
        add_action('show_user_profile', [$this, 'renderUserProfileMFASection']);
        add_action('edit_user_profile', [$this, 'renderUserProfileMFASection']);
        add_action('personal_options_update', [$this, 'saveUserProfileMFASection']);
        add_action('edit_user_profile_update', [$this, 'saveUserProfileMFASection']);
    }
    
    /**
     * Create database tables for MFA
     */
    private function createTables() {
        global $wpdb;
        
        // Ensure database is properly initialized
        if (!$this->db) {
            return;
        }
        
        $charset_collate = $wpdb->get_charset_collate();
        $table_name = $this->table_name;
        
        // SQL for trusted devices table
        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            device_id varchar(64) NOT NULL,
            device_name varchar(255) NOT NULL,
            ip_address varchar(45) NOT NULL,
            user_agent text NOT NULL,
            trusted tinyint(1) NOT NULL DEFAULT 0,
            last_used datetime DEFAULT CURRENT_TIMESTAMP,
            expires datetime NOT NULL,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY device_id (device_id),
            KEY user_device (user_id, device_id)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    /**
     * Register MFA settings
     */
    public function registerSettings() {
        // Register MFA settings
        register_setting('gdpr_framework_settings', 'gdpr_mfa_required_roles', [
            'type' => 'array',
            'default' => ['administrator'],
            'sanitize_callback' => [$this, 'sanitizeMFARoles']
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_mfa_device_expiry', [
            'type' => 'integer',
            'default' => 30,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_mfa_enforce_secure_connection', [
            'type' => 'boolean',
            'default' => 1,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_mfa_ip_restrictions', [
            'type' => 'string',
            'default' => '',
            'sanitize_callback' => [$this, 'sanitizeIPRestrictions']
        ]);
        
        // Add settings section
        add_settings_section(
            'gdpr_mfa_section',
            __('Multi-Factor Authentication Settings', 'wp-gdpr-framework'),
            [$this, 'renderMFASection'],
            'gdpr_framework_settings'
        );
        
        // Add settings fields
        add_settings_field(
            'gdpr_mfa_required_roles',
            __('Require MFA for Roles', 'wp-gdpr-framework'),
            [$this, 'renderMFARolesField'],
            'gdpr_framework_settings',
            'gdpr_mfa_section'
        );
        
        add_settings_field(
            'gdpr_mfa_device_expiry',
            __('Trusted Device Expiry', 'wp-gdpr-framework'),
            [$this, 'renderDeviceExpiryField'],
            'gdpr_framework_settings',
            'gdpr_mfa_section'
        );
        
        add_settings_field(
            'gdpr_mfa_enforce_secure_connection',
            __('Enforce Secure Connection', 'wp-gdpr-framework'),
            [$this, 'renderSecureConnectionField'],
            'gdpr_framework_settings',
            'gdpr_mfa_section'
        );
        
        add_settings_field(
            'gdpr_mfa_ip_restrictions',
            __('IP Address Restrictions', 'wp-gdpr-framework'),
            [$this, 'renderIPRestrictionsField'],
            'gdpr_framework_settings',
            'gdpr_mfa_section'
        );
    }
    
    /**
     * Render MFA settings section
     */
    public function renderMFASection() {
        echo '<p>' . 
             esc_html__('Configure multi-factor authentication settings to protect sensitive GDPR operations as required by Article 32.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render MFA required roles field
     */
    public function renderMFARolesField() {
        $required_roles = get_option('gdpr_mfa_required_roles', ['administrator']);
        
        // Get all roles
        $roles = wp_roles()->get_names();
        
        echo '<fieldset>';
        
        foreach ($roles as $role_id => $role_name) {
            $checked = in_array($role_id, $required_roles) ? 'checked' : '';
            
            echo '<label>';
            echo '<input type="checkbox" name="gdpr_mfa_required_roles[]" value="' . esc_attr($role_id) . '" ' . $checked . '> ';
            echo esc_html($role_name);
            echo '</label><br>';
        }
        
        echo '<p class="description">' . 
             esc_html__('Select roles that will be required to set up and use multi-factor authentication.', 'wp-gdpr-framework') . 
             '</p>';
        echo '</fieldset>';
    }
    
    /**
     * Render device expiry field
     */
    public function renderDeviceExpiryField() {
        $expiry_days = get_option('gdpr_mfa_device_expiry', 30);
        
        echo '<input type="number" name="gdpr_mfa_device_expiry" value="' . esc_attr($expiry_days) . '" min="1" max="365" class="small-text"> ' . 
             esc_html__('days', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('Number of days a trusted device will be remembered before requiring MFA verification again.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render secure connection field
     */
    public function renderSecureConnectionField() {
        $enforce_secure = get_option('gdpr_mfa_enforce_secure_connection', 1);
        
        echo '<input type="checkbox" name="gdpr_mfa_enforce_secure_connection" value="1" ' . checked(1, $enforce_secure, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Only allow MFA over HTTPS connections (strongly recommended).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render IP restrictions field
     */
    public function renderIPRestrictionsField() {
        $ip_restrictions = get_option('gdpr_mfa_ip_restrictions', '');
        
        echo '<textarea name="gdpr_mfa_ip_restrictions" rows="5" cols="50" class="large-text code">' . 
             esc_textarea($ip_restrictions) . 
             '</textarea>';
             
        echo '<p class="description">' . 
             esc_html__('Enter IP addresses or CIDR ranges to allow (one per line). Leave empty to allow all IPs. Example: 192.168.1.0/24', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Sanitize MFA roles
     */
    public function sanitizeMFARoles($roles) {
        if (!is_array($roles)) {
            return ['administrator'];
        }
        
        // Make sure administrator is always included
        if (!in_array('administrator', $roles)) {
            $roles[] = 'administrator';
        }
        
        return array_map('sanitize_text_field', $roles);
    }
    
    /**
     * Sanitize IP restrictions
     */
    public function sanitizeIPRestrictions($input) {
        $ips = explode("\n", $input);
        $valid_ips = [];
        
        foreach ($ips as $ip) {
            $ip = trim($ip);
            
            if (empty($ip)) {
                continue;
            }
            
            // Validate IPv4 address
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $valid_ips[] = $ip;
                continue;
            }
            
            // Validate IPv6 address
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $valid_ips[] = $ip;
                continue;
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
     * Generate a TOTP secret key
     */
    public function generateTOTPSecret() {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 characters
        $secret = '';
        
        if (function_exists('random_bytes')) {
            $bytes = random_bytes($this->secret_length);
            for ($i = 0; $i < $this->secret_length; $i++) {
                $secret .= $chars[ord($bytes[$i]) & 31];
            }
        } else if (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($this->secret_length, $crypto_strong);
            if (!$crypto_strong) {
                throw new \Exception('Cannot generate cryptographically secure random bytes');
            }
            for ($i = 0; $i < $this->secret_length; $i++) {
                $secret .= $chars[ord($bytes[$i]) & 31];
            }
        } else {
            // Fallback to less secure method
            for ($i = 0; $i < $this->secret_length; $i++) {
                $secret .= $chars[mt_rand(0, 31)];
            }
        }
        
        return $secret;
    }
    
    /**
     * Verify a TOTP code
     */
    public function verifyTOTPCode($secret, $code, $window = 1) {
        if (empty($secret) || empty($code) || !is_numeric($code) || strlen($code) !== 6) {
            return false;
        }
        
        // Check for valid base32 secret
        if (!preg_match('/^[A-Z234567]+$/', $secret)) {
            return false;
        }
        
        // Base32 decode the secret
        $secret = $this->base32Decode($secret);
        
        // Get current time in seconds
        $timestamp = floor(time() / 30);
        
        // Check codes in window
        for ($i = -$window; $i <= $window; $i++) {
            $check_timestamp = $timestamp + $i;
            $check_code = $this->generateTOTPCodeAtTimestamp($secret, $check_timestamp);
            
            if ($check_code === (int)$code) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate a TOTP code at a specific timestamp
     */
    private function generateTOTPCodeAtTimestamp($secret, $timestamp) {
        // Pack timestamp as big-endian 64-bit value
        $time = pack('N*', 0, $timestamp);
        
        // Generate HMAC-SHA1 hash
        $hash = hash_hmac('sha1', $time, $secret, true);
        
        // Get offset based on last nibble of hash
        $offset = ord($hash[19]) & 0x0F;
        
        // Get 4 bytes starting at offset
        $value = ((ord($hash[$offset]) & 0x7F) << 24) |
                 ((ord($hash[$offset + 1]) & 0xFF) << 16) |
                 ((ord($hash[$offset + 2]) & 0xFF) << 8) |
                 (ord($hash[$offset + 3]) & 0xFF);
        
        // Calculate modulo and ensure 6 digits
        return str_pad($value % 1000000, 6, '0', STR_PAD_LEFT);
    }
    
    /**
     * Base32 decode
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
     * Check if a user requires MFA
     */
    public function userRequiresMFA($user_id) {
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return false;
        }
        
        $required_roles = get_option('gdpr_mfa_required_roles', ['administrator']);
        
        foreach ($user->roles as $role) {
            if (in_array($role, $required_roles)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if user has MFA enabled
     */
    public function userHasMFA($user_id) {
        return !empty(get_user_meta($user_id, 'gdpr_mfa_secret', true));
    }
    
    /**
     * Set up MFA for a user
     */
    public function setupMFA($user_id, $secret = null) {
        if (!$secret) {
            $secret = $this->generateTOTPSecret();
        }
        
        // Store secret
        update_user_meta($user_id, 'gdpr_mfa_secret', $secret);
        update_user_meta($user_id, 'gdpr_mfa_enabled', true);
        
        // Get username for display
        $user = get_user_by('id', $user_id);
        $username = $user ? $user->user_login : "user{$user_id}";
        
        // Generate QR code data
        $site_name = get_bloginfo('name');
        $site_name = preg_replace('/[^a-zA-Z0-9\s]/', '', $site_name); // Remove special chars
        $totp_url = "otpauth://totp/{$site_name}:{$username}?secret={$secret}&issuer={$site_name}";
        
        return [
            'secret' => $secret,
            'qr_url' => $totp_url
        ];
    }
    
    /**
     * Check MFA requirements after login
     */
    public function checkMFARequirements($username, $user) {
        if (!$user instanceof \WP_User) {
            return;
        }
        
        $user_id = $user->ID;
        
        // Check if user requires MFA
        if (!$this->userRequiresMFA($user_id)) {
            return;
        }
        
        // Check if MFA is already set up
        if (!$this->userHasMFA($user_id)) {
            // Redirect to MFA setup page
            $setup_url = add_query_arg([
                'action' => 'gdpr_mfa_setup',
                'user_id' => $user_id,
                'nonce' => wp_create_nonce('gdpr_mfa_setup_' . $user_id)
            ], admin_url('admin-post.php'));
            
            wp_safe_redirect($setup_url);
            exit;
        }
        
        // Check if the current device is trusted
        $device_id = $this->getCurrentDeviceId($user_id);
        if ($this->isDeviceTrusted($user_id, $device_id)) {
            // Device is trusted, login allowed
            $this->updateDeviceLastUsed($user_id, $device_id);
            return;
        }
        
        // Device not trusted, require MFA verification
        $verify_url = add_query_arg([
            'action' => 'gdpr_mfa_verify',
            'user_id' => $user_id,
            'nonce' => wp_create_nonce('gdpr_mfa_verify_' . $user_id)
        ], admin_url('admin-post.php'));
        
        wp_safe_redirect($verify_url);
        exit;
    }
    
    /**
     * Handle MFA setup request
     */
    public function handleMFASetup() {
        if (!isset($_GET['user_id']) || !isset($_GET['nonce'])) {
            wp_die(__('Invalid request.', 'wp-gdpr-framework'));
        }
        
        $user_id = absint($_GET['user_id']);
        $nonce = sanitize_text_field($_GET['nonce']);
        
        if (!wp_verify_nonce($nonce, 'gdpr_mfa_setup_' . $user_id)) {
            wp_die(__('Security verification failed.', 'wp-gdpr-framework'));
        }
        
        // Check if user is logged in as the correct user
        if (!is_user_logged_in() || get_current_user_id() !== $user_id) {
            wp_die(__('You must be logged in as this user to set up MFA.', 'wp-gdpr-framework'));
        }
        
        // Set up MFA
        $mfa_data = $this->setupMFA($user_id);
        
        // Load template for setup
        $this->loadMFASetupTemplate($user_id, $mfa_data);
        exit;
    }
    
    /**
     * Handle MFA verification request
     */
    public function handleMFAVerification() {
        if (!isset($_GET['user_id']) || !isset($_GET['nonce'])) {
            wp_die(__('Invalid request.', 'wp-gdpr-framework'));
        }
        
        $user_id = absint($_GET['user_id']);
        $nonce = sanitize_text_field($_GET['nonce']);
        
        if (!wp_verify_nonce($nonce, 'gdpr_mfa_verify_' . $user_id)) {
            wp_die(__('Security verification failed.', 'wp-gdpr-framework'));
        }
        
        // Check if user is logged in as the correct user
        if (!is_user_logged_in() || get_current_user_id() !== $user_id) {
            wp_die(__('You must be logged in as this user to verify MFA.', 'wp-gdpr-framework'));
        }
        
        // Get MFA secret
        $secret = get_user_meta($user_id, 'gdpr_mfa_secret', true);
        
        if (empty($secret)) {
            // Redirect to setup if secret doesn't exist
            $setup_url = add_query_arg([
                'action' => 'gdpr_mfa_setup',
                'user_id' => $user_id,
                'nonce' => wp_create_nonce('gdpr_mfa_setup_' . $user_id)
            ], admin_url('admin-post.php'));
            
            wp_safe_redirect($setup_url);
            exit;
        }
        
        // Load template for verification
        $this->loadMFAVerifyTemplate($user_id);
        exit;
    }
    
    /**
     * Handle MFA reset request
     */
    public function handleMFAReset() {
        if (!isset($_GET['user_id']) || !isset($_GET['nonce'])) {
            wp_die(__('Invalid request.', 'wp-gdpr-framework'));
        }
        
        $user_id = absint($_GET['user_id']);
        $nonce = sanitize_text_field($_GET['nonce']);
        
        if (!wp_verify_nonce($nonce, 'gdpr_mfa_reset_' . $user_id)) {
            wp_die(__('Security verification failed.', 'wp-gdpr-framework'));
        }
        
        // Check if user is logged in as administrator or is the user themselves
        if (!is_user_logged_in() || (!current_user_can('administrator') && get_current_user_id() !== $user_id)) {
            wp_die(__('You do not have permission to reset MFA.', 'wp-gdpr-framework'));
        }
        
        // Reset MFA
        delete_user_meta($user_id, 'gdpr_mfa_secret');
        delete_user_meta($user_id, 'gdpr_mfa_enabled');
        
        // Delete trusted devices
        global $wpdb;
        $wpdb->delete($this->table_name, ['user_id' => $user_id]);
        
        // Log the reset
        do_action('gdpr_mfa_reset', $user_id, get_current_user_id());
        
        // Redirect to profile
        $redirect_url = get_edit_user_link($user_id);
        if (empty($redirect_url)) {
            $redirect_url = admin_url();
        }
        
        wp_safe_redirect(add_query_arg('mfa_reset', '1', $redirect_url));
        exit;
    }
    
    /**
     * AJAX handler for verifying MFA code
     */
    public function ajaxVerifyCode() {
        check_ajax_referer('gdpr_mfa_verify', 'nonce');
        
        $user_id = get_current_user_id();
        if (!$user_id) {
            wp_send_json_error(['message' => __('You must be logged in.', 'wp-gdpr-framework')]);
        }
        
        $code = isset($_POST['code']) ? sanitize_text_field($_POST['code']) : '';
        $trust_device = isset($_POST['trust_device']) && $_POST['trust_device'] === '1';
        
        if (empty($code)) {
            wp_send_json_error(['message' => __('Please enter a verification code.', 'wp-gdpr-framework')]);
        }
        
        // Get MFA secret
        $secret = get_user_meta($user_id, 'gdpr_mfa_secret', true);
        
        if (empty($secret)) {
            wp_send_json_error(['message' => __('MFA not set up for this user.', 'wp-gdpr-framework')]);
        }
        
        // Verify code
        if (!$this->verifyTOTPCode($secret, $code)) {
            // Log failed attempt
            do_action('gdpr_mfa_failed', $user_id, [
                'ip_address' => $this->getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);
            
            wp_send_json_error(['message' => __('Invalid verification code. Please try again.', 'wp-gdpr-framework')]);
        }
        
        // If trust device is selected, save device info
        if ($trust_device) {
            $this->trustCurrentDevice($user_id);
        }
        
        // Log successful MFA
        do_action('gdpr_mfa_success', $user_id);
        
        wp_send_json_success([
            'message' => __('Verification successful.', 'wp-gdpr-framework'),
            'redirect' => admin_url()
        ]);
    }
    
    /**
     * AJAX handler for trusting device
     */
    public function ajaxTrustDevice() {
        check_ajax_referer('gdpr_trust_device', 'nonce');
        
        $user_id = get_current_user_id();
        if (!$user_id) {
            wp_send_json_error(['message' => __('You must be logged in.', 'wp-gdpr-framework')]);
        }
        
        // Trust the current device
        $this->trustCurrentDevice($user_id);
        
        wp_send_json_success(['message' => __('Device trusted.', 'wp-gdpr-framework')]);
    }
    
    /**
     * Generate a device ID for the current device
     */
    private function getCurrentDeviceId($user_id) {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = $this->getClientIP();
        
        // Create a unique device ID based on multiple factors
        $data = $user_id . $user_agent . $ip;
        return hash('sha256', $data);
    }
    
    /**
     * Check if a device is trusted
     */
    private function isDeviceTrusted($user_id, $device_id) {
        global $wpdb;
        
        $query = $wpdb->prepare(
            "SELECT id FROM {$this->table_name} 
             WHERE user_id = %d 
             AND device_id = %s 
             AND trusted = 1 
             AND expires > NOW()",
            $user_id,
            $device_id
        );
        
        return (bool) $wpdb->get_var($query);
    }
    
    /**
     * Update last used time for a device
     */
    private function updateDeviceLastUsed($user_id, $device_id) {
        global $wpdb;
        
        $wpdb->update(
            $this->table_name,
            ['last_used' => current_time('mysql')],
            [
                'user_id' => $user_id,
                'device_id' => $device_id
            ]
        );
    }
    
    /**
     * Trust the current device
     */
    private function trustCurrentDevice($user_id) {
        global $wpdb;
        
        $device_id = $this->getCurrentDeviceId($user_id);
        $device_name = $this->getDeviceName();
        $ip = $this->getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Calculate expiry date
        $expiry_days = get_option('gdpr_mfa_device_expiry', 30);
        $expires = date('Y-m-d H:i:s', strtotime("+{$expiry_days} days"));
        
        // Check if device already exists
        $device_exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$this->table_name} WHERE user_id = %d AND device_id = %s",
            $user_id,
            $device_id
        ));
        
        if ($device_exists) {
            // Update existing device
            $wpdb->update(
                $this->table_name,
                [
                    'trusted' => 1,
                    'last_used' => current_time('mysql'),
                    'expires' => $expires,
                    'ip_address' => $ip,
                    'user_agent' => $user_agent
                ],
                [
                    'user_id' => $user_id,
                    'device_id' => $device_id
                ]
            );
        } else {
            // Insert new device
            $wpdb->insert(
                $this->table_name,
                [
                    'user_id' => $user_id,
                    'device_id' => $device_id,
                    'device_name' => $device_name,
                    'ip_address' => $ip,
                    'user_agent' => $user_agent,
                    'trusted' => 1,
                    'last_used' => current_time('mysql'),
                    'expires' => $expires
                ]
            );
        }
        
        // Log device trust
        do_action('gdpr_device_trusted', $user_id, [
            'device_id' => $device_id,
            'device_name' => $device_name,
            'ip_address' => $ip,
            'expires' => $expires
        ]);
        
        return true;
    }
    
    /**
     * Get device name based on user agent
     */
    private function getDeviceName() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Default device name
        $device_name = __('Unknown Device', 'wp-gdpr-framework');
        
        if (empty($user_agent)) {
            return $device_name;
        }
        
        // Try to detect device type and OS
        $device_type = 'Computer';
        
        if (preg_match('/mobile|android|iphone|ipad|ipod/i', $user_agent)) {
            $device_type = 'Mobile';
            
            if (preg_match('/ipad/i', $user_agent)) {
                $device_type = 'Tablet';
            }
        } elseif (preg_match('/tablet/i', $user_agent)) {
            $device_type = 'Tablet';
        }
        
        // Detect OS
        $os = 'Unknown';
        
        if (preg_match('/windows|win32/i', $user_agent)) {
            $os = 'Windows';
        } elseif (preg_match('/macintosh|mac os x/i', $user_agent)) {
            $os = 'Mac';
        } elseif (preg_match('/linux/i', $user_agent)) {
            $os = 'Linux';
        } elseif (preg_match('/android/i', $user_agent)) {
            $os = 'Android';
        } elseif (preg_match('/iphone|ipad|ipod/i', $user_agent)) {
            $os = 'iOS';
        }
        
        // Detect browser
        $browser = 'Unknown';
        
        if (preg_match('/msie|trident/i', $user_agent)) {
            $browser = 'Internet Explorer';
        } elseif (preg_match('/firefox/i', $user_agent)) {
            $browser = 'Firefox';
        } elseif (preg_match('/chrome/i', $user_agent)) {
            $browser = 'Chrome';
        } elseif (preg_match('/safari/i', $user_agent)) {
            $browser = 'Safari';
        } elseif (preg_match('/opera|opr/i', $user_agent)) {
            $browser = 'Opera';
        } elseif (preg_match('/edge/i', $user_agent)) {
            $browser = 'Edge';
        }
        
        // Combine info into device name
        $device_name = sprintf(
            '%s - %s (%s)',
            $device_type,
            $os,
            $browser
        );
        
        return $device_name;
    }
    
    /**
     * Get client IP address
     */
    private function getClientIP() {
        $ip = '';
        
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        return filter_var($ip, FILTER_VALIDATE_IP) ?: '0.0.0.0';
    }
    
    /**
     * Clean up expired device records
     */
    public function cleanupExpiredDevices() {
        global $wpdb;
        
        return $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE expires < NOW()"
        );
    }
    
    /**
     * Load MFA setup template
     */
    private function loadMFASetupTemplate($user_id, $mfa_data) {
        // Create QR code link for Google Charts
        $qr_code_url = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . urlencode($mfa_data['qr_url']);
        
        $template_file = GDPR_FRAMEWORK_PATH . 'templates/admin/mfa-setup.php';
        
        if (file_exists($template_file)) {
            include $template_file;
        } else {
            // Fallback template
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title><?php _e('Set Up Two-Factor Authentication', 'wp-gdpr-framework'); ?></title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                        line-height: 1.5;
                        padding: 2rem;
                        max-width: 600px;
                        margin: 0 auto;
                    }
                    .qr-code {
                        text-align: center;
                        margin: 2rem 0;
                    }
                    .code-container {
                        background: #f5f5f5;
                        padding: 0.5rem;
                        font-family: monospace;
                        text-align: center;
                        font-size: 1.2rem;
                        letter-spacing: 0.2rem;
                        margin: 1rem 0;
                    }
                    .form-container {
                        margin: 2rem 0;
                    }
                    input[type="text"] {
                        font-size: 1.2rem;
                        padding: 0.5rem;
                        width: 100%;
                        max-width: 200px;
                        text-align: center;
                        letter-spacing: 0.2rem;
                    }
                    button {
                        background: #0085ba;
                        border: none;
                        color: white;
                        padding: 0.5rem 1rem;
                        font-size: 1rem;
                        cursor: pointer;
                    }
                    .error-message {
                        color: #d63638;
                        display: none;
                    }
                    .success-message {
                        color: #00a32a;
                        display: none;
                    }
                    .steps {
                        counter-reset: step-counter;
                        list-style: none;
                        padding: 0;
                    }
                    .steps li {
                        counter-increment: step-counter;
                        margin-bottom: 1rem;
                        position: relative;
                        padding-left: 2.5rem;
                    }
                    .steps li::before {
                        content: counter(step-counter);
                        background: #0085ba;
                        color: white;
                        font-weight: bold;
                        width: 1.5rem;
                        height: 1.5rem;
                        border-radius: 50%;
                        display: inline-block;
                        text-align: center;
                        line-height: 1.5rem;
                        position: absolute;
                        left: 0;
                        top: 0.2rem;
                    }
                </style>
            </head>
            <body>
                <h1><?php _e('Set Up Two-Factor Authentication', 'wp-gdpr-framework'); ?></h1>
                
                <p><?php _e('For enhanced security when handling GDPR-sensitive data, two-factor authentication is required for your account. Please follow the steps below to complete setup.', 'wp-gdpr-framework'); ?></p>
                
                <ol class="steps">
                    <li>
                        <?php _e('Install a TOTP authenticator app on your device, such as Google Authenticator, Microsoft Authenticator, or Authy.', 'wp-gdpr-framework'); ?>
                    </li>
                    <li>
                        <?php _e('Scan the QR code below with your authenticator app or manually enter the secret key.', 'wp-gdpr-framework'); ?>
                    </li>
                    <li>
                        <?php _e('Enter the 6-digit verification code provided by your authenticator app to complete setup.', 'wp-gdpr-framework'); ?>
                    </li>
                </ol>
                
                <div class="qr-code">
                    <img src="<?php echo esc_url($qr_code_url); ?>" alt="QR Code">
                </div>
                
                <p><?php _e('If you cannot scan the QR code, enter this secret key manually:', 'wp-gdpr-framework'); ?></p>
                
                <div class="code-container">
                    <?php echo esc_html($mfa_data['secret']); ?>
                </div>
                
                <div class="form-container">
                    <p><?php _e('Enter the verification code from your authenticator app:', 'wp-gdpr-framework'); ?></p>
                    
                    <form id="mfa-setup-form">
                        <?php wp_nonce_field('gdpr_mfa_verify', 'mfa_nonce'); ?>
                        <input type="hidden" name="user_id" value="<?php echo esc_attr($user_id); ?>">
                        <input type="text" name="code" id="verification-code" autocomplete="off" pattern="[0-9]*" inputmode="numeric" maxlength="6" required>
                        <p>
                            <button type="submit"><?php _e('Verify and Activate', 'wp-gdpr-framework'); ?></button>
                        </p>
                        <p class="error-message" id="error-message"></p>
                        <p class="success-message" id="success-message"></p>
                    </form>
                </div>
                
                <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        const form = document.getElementById('mfa-setup-form');
                        const errorMessage = document.getElementById('error-message');
                        const successMessage = document.getElementById('success-message');
                        
                        form.addEventListener('submit', function(e) {
                            e.preventDefault();
                            
                            const code = document.getElementById('verification-code').value;
                            
                            // Validate code format
                            if (!code.match(/^\d{6}$/)) {
                                errorMessage.textContent = '<?php echo esc_js(__('Please enter a 6-digit verification code.', 'wp-gdpr-framework')); ?>';
                                errorMessage.style.display = 'block';
                                successMessage.style.display = 'none';
                                return;
                            }
                            
                            // Send request to verify code
                            const xhr = new XMLHttpRequest();
                            xhr.open('POST', '<?php echo esc_js(admin_url('admin-ajax.php')); ?>');
                            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                            
                            const formData = new FormData(form);
                            formData.append('action', 'gdpr_verify_mfa_code');
                            formData.append('nonce', '<?php echo wp_create_nonce('gdpr_mfa_verify'); ?>');
                            formData.append('trust_device', '1');
                            
                            let params = new URLSearchParams();
                            for (let pair of formData.entries()) {
                                params.append(pair[0], pair[1]);
                            }
                            
                            xhr.send(params.toString());
                            
                            xhr.onload = function() {
                                try {
                                    const response = JSON.parse(xhr.responseText);
                                    
                                    if (response.success) {
                                        errorMessage.style.display = 'none';
                                        successMessage.textContent = response.data.message;
                                        successMessage.style.display = 'block';
                                        
                                        // Redirect after successful setup
                                        setTimeout(function() {
                                            window.location.href = response.data.redirect || '<?php echo esc_js(admin_url()); ?>';
                                        }, 2000);
                                    } else {
                                        errorMessage.textContent = response.data.message;
                                        errorMessage.style.display = 'block';
                                        successMessage.style.display = 'none';
                                    }
                                } catch (e) {
                                    errorMessage.textContent = '<?php echo esc_js(__('An unexpected error occurred. Please try again.', 'wp-gdpr-framework')); ?>';
                                    errorMessage.style.display = 'block';
                                    successMessage.style.display = 'none';
                                }
                            };
                            
                            xhr.onerror = function() {
                                errorMessage.textContent = '<?php echo esc_js(__('Network error. Please try again.', 'wp-gdpr-framework')); ?>';
                                errorMessage.style.display = 'block';
                                successMessage.style.display = 'none';
                            };
                        });
                    });
                </script>
            </body>
            </html>
            <?php
        }
    }
    
    /**
     * Load MFA verification template
     */
    private function loadMFAVerifyTemplate($user_id) {
        $template_file = GDPR_FRAMEWORK_PATH . 'templates/admin/mfa-verify.php';
        
        if (file_exists($template_file)) {
            include $template_file;
        } else {
            // Fallback template
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title><?php _e('Verify Two-Factor Authentication', 'wp-gdpr-framework'); ?></title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                        line-height: 1.5;
                        padding: 2rem;
                        max-width: 600px;
                        margin: 0 auto;
                    }
                    .form-container {
                        margin: 2rem 0;
                    }
                    input[type="text"] {
                        font-size: 1.2rem;
                        padding: 0.5rem;
                        width: 100%;
                        max-width: 200px;
                        text-align: center;
                        letter-spacing: 0.2rem;
                    }
                    button {
                        background: #0085ba;
                        border: none;
                        color: white;
                        padding: 0.5rem 1rem;
                        font-size: 1rem;
                        cursor: pointer;
                    }
                    .error-message {
                        color: #d63638;
                        display: none;
                    }
                    .success-message {
                        color: #00a32a;
                        display: none;
                    }
                    .trust-device-container {
                        margin-top: 1rem;
                    }
                </style>
            </head>
            <body>
                <h1><?php _e('Verify Two-Factor Authentication', 'wp-gdpr-framework'); ?></h1>
                
                <p><?php _e('Please enter the verification code from your authenticator app to continue.', 'wp-gdpr-framework'); ?></p>
                
                <div class="form-container">
                    <form id="mfa-verify-form">
                        <?php wp_nonce_field('gdpr_mfa_verify', 'mfa_nonce'); ?>
                        <input type="hidden" name="user_id" value="<?php echo esc_attr($user_id); ?>">
                        <input type="text" name="code" id="verification-code" autocomplete="off" pattern="[0-9]*" inputmode="numeric" maxlength="6" required autofocus>
                        
                        <div class="trust-device-container">
                            <label>
                                <input type="checkbox" name="trust_device" value="1" checked>
                                <?php _e('Trust this device for 30 days', 'wp-gdpr-framework'); ?>
                            </label>
                        </div>
                        
                        <p>
                            <button type="submit"><?php _e('Verify', 'wp-gdpr-framework'); ?></button>
                        </p>
                        <p class="error-message" id="error-message"></p>
                        <p class="success-message" id="success-message"></p>
                    </form>
                </div>
                
                <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        const form = document.getElementById('mfa-verify-form');
                        const errorMessage = document.getElementById('error-message');
                        const successMessage = document.getElementById('success-message');
                        
                        form.addEventListener('submit', function(e) {
                            e.preventDefault();
                            
                            const code = document.getElementById('verification-code').value;
                            
                            // Validate code format
                            if (!code.match(/^\d{6}$/)) {
                                errorMessage.textContent = '<?php echo esc_js(__('Please enter a 6-digit verification code.', 'wp-gdpr-framework')); ?>';
                                errorMessage.style.display = 'block';
                                successMessage.style.display = 'none';
                                return;
                            }
                            
                            // Send request to verify code
                            const xhr = new XMLHttpRequest();
                            xhr.open('POST', '<?php echo esc_js(admin_url('admin-ajax.php')); ?>');
                            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                            
                            const formData = new FormData(form);
                            formData.append('action', 'gdpr_verify_mfa_code');
                            formData.append('nonce', '<?php echo wp_create_nonce('gdpr_mfa_verify'); ?>');
                            
                            let params = new URLSearchParams();
                            for (let pair of formData.entries()) {
                                params.append(pair[0], pair[1]);
                            }
                            
                            xhr.send(params.toString());
                            
                            xhr.onload = function() {
                                try {
                                    const response = JSON.parse(xhr.responseText);
                                    
                                    if (response.success) {
                                        errorMessage.style.display = 'none';
                                        successMessage.textContent = response.data.message;
                                        successMessage.style.display = 'block';
                                        
                                        // Redirect after successful verification
                                        setTimeout(function() {
                                            window.location.href = response.data.redirect || '<?php echo esc_js(admin_url()); ?>';
                                        }, 2000);
                                    } else {
                                        errorMessage.textContent = response.data.message;
                                        errorMessage.style.display = 'block';
                                        successMessage.style.display = 'none';
                                    }
                                } catch (e) {
                                    errorMessage.textContent = '<?php echo esc_js(__('An unexpected error occurred. Please try again.', 'wp-gdpr-framework')); ?>';
                                    errorMessage.style.display = 'block';
                                    successMessage.style.display = 'none';
                                }
                            };
                            
                            xhr.onerror = function() {
                                errorMessage.textContent = '<?php echo esc_js(__('Network error. Please try again.', 'wp-gdpr-framework')); ?>';
                                errorMessage.style.display = 'block';
                                successMessage.style.display = 'none';
                            };
                        });
                    });
                </script>
            </body>
            </html>
            <?php
        }
    }
    
    /**
     * Render MFA section in user profile
     */
    public function renderUserProfileMFASection($user) {
        if (!$this->userRequiresMFA($user->ID)) {
            return;
        }
        
        $has_mfa = $this->userHasMFA($user->ID);
        
        ?>
        <h2><?php _e('Multi-Factor Authentication', 'wp-gdpr-framework'); ?></h2>
        <table class="form-table">
            <tr>
                <th><?php _e('MFA Status', 'wp-gdpr-framework'); ?></th>
                <td>
                    <?php if ($has_mfa): ?>
                        <span style="color: #00a32a;">
                            <span class="dashicons dashicons-yes"></span>
                            <?php _e('Enabled', 'wp-gdpr-framework'); ?>
                        </span>
                    <?php else: ?>
                        <span style="color: #d63638;">
                            <span class="dashicons dashicons-no"></span>
                            <?php _e('Not Enabled', 'wp-gdpr-framework'); ?>
                        </span>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th><?php _e('Actions', 'wp-gdpr-framework'); ?></th>
                <td>
                    <?php if ($has_mfa): ?>
                        <a href="<?php echo esc_url(wp_nonce_url(
                            add_query_arg([
                                'action' => 'gdpr_mfa_reset',
                                'user_id' => $user->ID
                            ], admin_url('admin-post.php')),
                            'gdpr_mfa_reset_' . $user->ID
                        )); ?>" class="button" onclick="return confirm('<?php esc_attr_e('Are you sure you want to reset MFA? The user will need to set it up again.', 'wp-gdpr-framework'); ?>');">
                            <?php _e('Reset MFA', 'wp-gdpr-framework'); ?>
                        </a>
                    <?php else: ?>
                        <a href="<?php echo esc_url(wp_nonce_url(
                            add_query_arg([
                                'action' => 'gdpr_mfa_setup',
                                'user_id' => $user->ID
                            ], admin_url('admin-post.php')),
                            'gdpr_mfa_setup_' . $user->ID
                        )); ?>" class="button button-primary">
                            <?php _e('Set Up MFA', 'wp-gdpr-framework'); ?>
                        </a>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <?php
    }
    
    /**
     * Save MFA settings from user profile
     */
    public function saveUserProfileMFASection($user_id) {
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        
        // Nothing to save directly, as MFA setup is done through separate flow
    }
}
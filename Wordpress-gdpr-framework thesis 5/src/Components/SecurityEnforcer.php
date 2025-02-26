<?php
namespace GDPRFramework\Components;

/**
 * Security Enforcement Workflow
 * 
 * Implements the security enforcement workflow as described in the security chapter:
 * 1. Data Access & Authentication Flow
 * 2. Data Modification & Encryption Flow
 */
class SecurityEnforcer {
    private $db;
    private $settings;
    private $components = [];
    private $enforcement_mode = 'basic'; // basic or advanced

    public function __construct($database, $settings) {
        $this->db = $database;
        $this->settings = $settings;
        
        // Load settings
        $this->enforcement_mode = get_option('gdpr_enforcement_mode', 'basic');
        
        // Initialize hooks
        $this->initializeHooks();
    }
    
    /**
     * Initialize hooks
     */
    private function initializeHooks() {
        // Register main security filters
        add_action('init', [$this, 'initializeComponents']);
        
        // Register data access hooks
        add_filter('gdpr_user_can_access_data', [$this, 'validateDataAccess'], 10, 3);
        
        // Register data modification hooks
        add_filter('gdpr_user_can_modify_data', [$this, 'validateDataModification'], 10, 3);
        add_action('gdpr_pre_data_modification', [$this, 'prepareDataModification'], 10, 3);
        add_action('gdpr_post_data_modification', [$this, 'logDataModification'], 10, 3);
        
        // Register settings access hooks
        add_filter('gdpr_user_can_access_settings', [$this, 'validateSettingsAccess'], 10, 2);
        
        // Register settings
        add_action('admin_init', [$this, 'registerSettings']);
        
        // Register security checks
        add_action('admin_init', [$this, 'runSecurityChecks']);
    }
    
    /**
     * Initialize security components
     */
    public function initializeComponents() {
        // Get GDPR Framework instance
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
        
        // Get components with existence checks
        if ($framework->getComponent('encryption')) {
            $this->components['encryption'] = $framework->getComponent('encryption');
        }
        
        if ($framework->getComponent('audit')) {
            $this->components['audit'] = $framework->getComponent('audit');
        }
        
        if ($framework->getComponent('rbac')) {
            $this->components['rbac'] = $framework->getComponent('rbac');
        }
        
        if ($framework->getComponent('mfa')) {
            $this->components['mfa'] = $framework->getComponent('mfa');
        }
        
        if ($framework->getComponent('api_security')) {
            $this->components['api_security'] = $framework->getComponent('api_security');
        }
    }
    
    /**
     * Register settings
     */
    public function registerSettings() {
        // Register enforcement mode setting
        register_setting('gdpr_framework_settings', 'gdpr_enforcement_mode', [
            'type' => 'string',
            'default' => 'basic',
            'sanitize_callback' => [$this, 'sanitizeEnforcementMode']
        ]);
        
        // Register security settings section
        add_settings_section(
            'gdpr_security_section',
            __('Security Enforcement', 'wp-gdpr-framework'),
            [$this, 'renderSecuritySection'],
            'gdpr_framework_settings'
        );
        
        // Add enforcement mode field
        add_settings_field(
            'gdpr_enforcement_mode',
            __('Enforcement Mode', 'wp-gdpr-framework'),
            [$this, 'renderEnforcementModeField'],
            'gdpr_framework_settings',
            'gdpr_security_section'
        );
    }
    
    /**
     * Render security section
     */
    public function renderSecuritySection() {
        echo '<p>' . 
             esc_html__('Configure the security enforcement mode for GDPR compliance.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render enforcement mode field
     */
    public function renderEnforcementModeField() {
        $mode = get_option('gdpr_enforcement_mode', 'basic');
        
        ?>
        <fieldset>
            <label>
                <input type="radio" name="gdpr_enforcement_mode" value="basic" <?php checked('basic', $mode); ?>>
                <?php _e('Basic Mode', 'wp-gdpr-framework'); ?>
            </label>
            <p class="description">
                <?php _e('Standard security enforcement suitable for most websites.', 'wp-gdpr-framework'); ?>
            </p>
            
            <br>
            
            <label>
                <input type="radio" name="gdpr_enforcement_mode" value="advanced" <?php checked('advanced', $mode); ?>>
                <?php _e('Advanced Mode', 'wp-gdpr-framework'); ?>
            </label>
            <p class="description">
                <?php _e('Strict security enforcement with additional validations and logging for high-security environments.', 'wp-gdpr-framework'); ?>
            </p>
        </fieldset>
        <?php
    }
    
    /**
     * Sanitize enforcement mode
     */
    public function sanitizeEnforcementMode($mode) {
        return in_array($mode, ['basic', 'advanced']) ? $mode : 'basic';
    }
    
    /**
     * Run security checks
     */
    public function runSecurityChecks() {
        // Only run in admin area
        if (!is_admin()) {
            return;
        }
        
        // Skip AJAX requests
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        
        // Check for encryption key
        $this->checkEncryptionKey();
        
        // Check for secure connection
        $this->checkSecureConnection();
        
        // Check for admin multi-factor authentication
        $this->checkAdminMFA();
    }
    
    /**
     * Check encryption key
     */
    private function checkEncryptionKey() {
        if (!isset($this->components['encryption'])) {
            return;
        }
        
        // Check if encryption is enabled
        $encryption_enabled = get_option('gdpr_enable_encryption', 1);
        if (!$encryption_enabled) {
            return;
        }
        
        // Check if key exists
        $key_exists = get_option('gdpr_encryption_key') || get_option('gdpr_encryption_keys');
        
        if (!$key_exists) {
            // Add admin notice for missing encryption key
            add_action('admin_notices', function() {
                echo '<div class="notice notice-error">';
                echo '<p><strong>' . esc_html__('GDPR Security Warning', 'wp-gdpr-framework') . '</strong></p>';
                echo '<p>' . esc_html__('Encryption is enabled but no encryption key is configured. Personal data will not be properly secured.', 'wp-gdpr-framework') . '</p>';
                echo '<p><a href="' . esc_url(admin_url('admin.php?page=gdpr-framework-settings#security')) . '" class="button">' . 
                     esc_html__('Configure Encryption', 'wp-gdpr-framework') . 
                     '</a></p>';
                echo '</div>';
            });
        }
    }
    
    /**
     * Check secure connection
     */
    private function checkSecureConnection() {
        // Only check on GDPR pages
        $is_gdpr_page = isset($_GET['page']) && strpos($_GET['page'], 'gdpr-framework') === 0;
        
        if (!$is_gdpr_page) {
            return;
        }
        
        // Check if site is using HTTPS
        if (!is_ssl()) {
            // Add admin notice for insecure connection
            add_action('admin_notices', function() {
                echo '<div class="notice notice-warning">';
                echo '<p><strong>' . esc_html__('GDPR Security Warning', 'wp-gdpr-framework') . '</strong></p>';
                echo '<p>' . esc_html__('You are accessing GDPR settings over an insecure connection. It is strongly recommended to use HTTPS for all GDPR-related operations.', 'wp-gdpr-framework') . '</p>';
                echo '</div>';
            });
        }
    }
    
    /**
     * Check admin MFA
     */
    private function checkAdminMFA() {
        // Only check for administrators
        if (!current_user_can('administrator')) {
            return;
        }
        
        // Only check on GDPR pages
        $is_gdpr_page = isset($_GET['page']) && strpos($_GET['page'], 'gdpr-framework') === 0;
        
        if (!$is_gdpr_page) {
            return;
        }
        
        // Skip check if MFA component is not available
        if (!isset($this->components['mfa'])) {
            return;
        }
        
        // Check if admin has MFA enabled
        $has_mfa = $this->components['mfa']->userHasMFA(get_current_user_id());
        
        if (!$has_mfa) {
            // Add admin notice for missing MFA
            add_action('admin_notices', function() {
                echo '<div class="notice notice-warning">';
                echo '<p><strong>' . esc_html__('GDPR Security Recommendation', 'wp-gdpr-framework') . '</strong></p>';
                echo '<p>' . esc_html__('Two-factor authentication is strongly recommended for administrators to enhance security for GDPR-related operations.', 'wp-gdpr-framework') . '</p>';
                echo '<p><a href="' . esc_url(wp_nonce_url(
                    add_query_arg([
                        'action' => 'gdpr_mfa_setup',
                        'user_id' => get_current_user_id()
                    ], admin_url('admin-post.php')),
                    'gdpr_mfa_setup_' . get_current_user_id()
                )) . '" class="button">' . 
                     esc_html__('Set Up Two-Factor Authentication', 'wp-gdpr-framework') . 
                     '</a></p>';
                echo '</div>';
            });
        }
    }
    
    /**
     * Validate data access
     * 
     * Implements the Data Access & Authentication Flow from the security chapter
     * 
     * @param bool $allowed Current access status
     * @param int $user_id User ID requesting access
     * @param array $data_type Type of data being accessed
     * @return bool Updated access status
     */
    public function validateDataAccess($allowed, $user_id, $data_type) {
        // If access is already denied, don't override
        if (!$allowed) {
            return false;
        }
        
        // Get current user ID
        $current_user_id = get_current_user_id();
        
        // Check if user is accessing their own data
        $own_data = ($current_user_id === $user_id);
        
        // Check if user has admin privileges
        $is_admin = current_user_can('manage_options');
        
        // Step 1: Check basic permissions
        if (!$own_data && !$is_admin) {
            // Regular users can only access their own data
            return false;
        }
        
        // Step 2: Apply RBAC if component is available
        if (isset($this->components['rbac'])) {
            // For own data
            if ($own_data && !$this->components['rbac']->currentUserCan('gdpr_access_own_data')) {
                return false;
            }
            
            // For other users' data
            if (!$own_data && !$this->components['rbac']->currentUserCan('gdpr_access_others_data')) {
                return false;
            }
        }
        
        // Step 3: Verify session if accessing sensitive data
        $is_sensitive = in_array($data_type, ['consent_history', 'personal_data', 'audit_log']);
        
        if ($is_sensitive && isset($this->components['rbac'])) {
            // Check for session timeout
            if ($this->components['rbac']->hasTimedOut($current_user_id)) {
                return false;
            }
        }
        
        // Step 4: Apply additional checks in advanced mode
        if ($this->enforcement_mode === 'advanced') {
            // Log the access attempt
            if (isset($this->components['audit'])) {
                $this->components['audit']->log(
                    $current_user_id,
                    'data_access_attempt',
                    sprintf(
                        __('User %d attempted to access %s data for user %d', 'wp-gdpr-framework'),
                        $current_user_id,
                        $data_type,
                        $user_id
                    ),
                    $is_sensitive ? 'medium' : 'low'
                );
            }
            
            // In advanced mode, require MFA for sensitive data access
            if ($is_sensitive && isset($this->components['mfa']) && $is_admin) {
                // Check if MFA is required and user has completed MFA
                $has_mfa = $this->components['mfa']->userHasMFA($current_user_id);
                
                if (!$has_mfa) {
                    // Log the denial due to missing MFA
                    if (isset($this->components['audit'])) {
                        $this->components['audit']->log(
                            $current_user_id,
                            'data_access_denied',
                            sprintf(
                                __('Access denied to %s data for user %d due to missing MFA', 'wp-gdpr-framework'),
                                $data_type,
                                $user_id
                            ),
                            'high'
                        );
                    }
                    
                    return false;
                }
            }
        }
        
        // Step 5: Log successful access
        if (isset($this->components['audit']) && $is_sensitive) {
            $this->components['audit']->log(
                $current_user_id,
                'data_access_granted',
                sprintf(
                    __('Access granted to %s data for user %d', 'wp-gdpr-framework'),
                    $data_type,
                    $user_id
                ),
                $is_sensitive ? 'medium' : 'low'
            );
        }
        
        return true;
    }
    
    /**
     * Validate data modification
     * 
     * Part of the Data Modification & Encryption Flow
     * 
     * @param bool $allowed Current modification status
     * @param int $user_id User ID whose data is being modified
     * @param string $data_type Type of data being modified
     * @return bool Updated modification status
     */
    public function validateDataModification($allowed, $user_id, $data_type) {
        // If modification is already denied, don't override
        if (!$allowed) {
            return false;
        }
        
        // Get current user ID
        $current_user_id = get_current_user_id();
        
        // Check if user is modifying their own data
        $own_data = ($current_user_id === $user_id);
        
        // Check if user has admin privileges
        $is_admin = current_user_can('manage_options');
        
        // Step 1: Check basic permissions
        if (!$own_data && !$is_admin) {
            // Regular users can only modify their own data
            return false;
        }
        
        // Step 2: Apply RBAC if component is available
        if (isset($this->components['rbac'])) {
            // For own data
            if ($own_data && !$this->components['rbac']->currentUserCan('gdpr_modify_own_data')) {
                return false;
            }
            
            // For other users' data
            if (!$own_data && !$this->components['rbac']->currentUserCan('gdpr_modify_others_data')) {
                return false;
            }
        }
        
        // Step 3: Verify session
        if (isset($this->components['rbac'])) {
            // Check for session timeout
            if ($this->components['rbac']->hasTimedOut($current_user_id)) {
                return false;
            }
        }
        
        // Step 4: Apply additional checks in advanced mode
        if ($this->enforcement_mode === 'advanced') {
            // Log the modification attempt
            if (isset($this->components['audit'])) {
                $this->components['audit']->log(
                    $current_user_id,
                    'data_modification_attempt',
                    sprintf(
                        __('User %d attempted to modify %s data for user %d', 'wp-gdpr-framework'),
                        $current_user_id,
                        $data_type,
                        $user_id
                    ),
                    'medium'
                );
            }
            
            // In advanced mode, require MFA for admin actions
            if (!$own_data && isset($this->components['mfa']) && $is_admin) {
                // Check if MFA is required and user has completed MFA
                $has_mfa = $this->components['mfa']->userHasMFA($current_user_id);
                
                if (!$has_mfa) {
                    // Log the denial due to missing MFA
                    if (isset($this->components['audit'])) {
                        $this->components['audit']->log(
                            $current_user_id,
                            'data_modification_denied',
                            sprintf(
                                __('Modification denied for %s data of user %d due to missing MFA', 'wp-gdpr-framework'),
                                $data_type,
                                $user_id
                            ),
                            'high'
                        );
                    }
                    
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /**
     * Prepare data modification
     * 
     * Part of the Data Modification & Encryption Flow
     * 
     * @param mixed $data Data to be modified
     * @param int $user_id User ID whose data is being modified
     * @param string $data_type Type of data being modified
     * @return mixed Processed data
     */
    public function prepareDataModification($data, $user_id, $data_type) {
        // Check if encryption is needed for this data type
        $encrypt_data = in_array($data_type, ['personal_data', 'contact_info', 'financial_data']);
        
        // Encrypt sensitive data if encryption component is available
        if ($encrypt_data && isset($this->components['encryption'])) {
            try {
                return $this->components['encryption']->encrypt($data);
            } catch (\Exception $e) {
                // Log encryption failure
                if (isset($this->components['audit'])) {
                    $this->components['audit']->log(
                        get_current_user_id(),
                        'data_encryption_failed',
                        sprintf(
                            __('Failed to encrypt %s data for user %d: %s', 'wp-gdpr-framework'),
                            $data_type,
                            $user_id,
                            $e->getMessage()
                        ),
                        'high'
                    );
                }
                
                // In advanced mode, block the modification if encryption fails
                if ($this->enforcement_mode === 'advanced') {
                    wp_die(
                        __('Data encryption failed. For security reasons, unencrypted sensitive data cannot be saved.', 'wp-gdpr-framework'),
                        __('Security Error', 'wp-gdpr-framework'),
                        ['response' => 500, 'back_link' => true]
                    );
                }
            }
        }
        
        // Return the data as-is if encryption not needed or failed
        return $data;
    }
    
    /**
     * Log data modification
     * 
     * Part of the Data Modification & Encryption Flow
     * 
     * @param mixed $data Modified data
     * @param int $user_id User ID whose data was modified
     * @param string $data_type Type of data that was modified
     */
    public function logDataModification($data, $user_id, $data_type) {
        // Log the modification if audit component is available
        if (isset($this->components['audit'])) {
            $current_user_id = get_current_user_id();
            $own_data = ($current_user_id === $user_id);
            
            $this->components['audit']->log(
                $current_user_id,
                'data_modified',
                sprintf(
                    __('User %d modified %s data for user %d', 'wp-gdpr-framework'),
                    $current_user_id,
                    $data_type,
                    $user_id
                ),
                $own_data ? 'low' : 'medium'
            );
        }
    }
    
    /**
     * Validate settings access
     * 
     * @param bool $allowed Current access status
     * @param string $setting_group Setting group being accessed
     * @return bool Updated access status
     */
    public function validateSettingsAccess($allowed, $setting_group) {
        // If access is already denied, don't override
        if (!$allowed) {
            return false;
        }
        
        // Check basic permission
        if (!current_user_can('manage_options')) {
            return false;
        }
        
        // Apply RBAC if component is available
        if (isset($this->components['rbac'])) {
            // Check for specific capability
            if (!$this->components['rbac']->currentUserCan('manage_gdpr_settings')) {
                return false;
            }
            
            // Check for session timeout
            if ($this->components['rbac']->hasTimedOut(get_current_user_id())) {
                return false;
            }
        }
        
        // Apply additional checks in advanced mode
        if ($this->enforcement_mode === 'advanced') {
            // Log the settings access
            if (isset($this->components['audit'])) {
                $this->components['audit']->log(
                    get_current_user_id(),
                    'settings_access',
                    sprintf(
                        __('User accessed %s settings', 'wp-gdpr-framework'),
                        $setting_group
                    ),
                    'medium'
                );
            }
            
            // In advanced mode, require MFA for sensitive settings
            $sensitive_settings = ['security', 'encryption', 'audit', 'api'];
            
            if (in_array($setting_group, $sensitive_settings) && isset($this->components['mfa'])) {
                // Check if MFA is required and user has completed MFA
                $has_mfa = $this->components['mfa']->userHasMFA(get_current_user_id());
                
                if (!$has_mfa) {
                    // Log the denial due to missing MFA
                    if (isset($this->components['audit'])) {
                        $this->components['audit']->log(
                            get_current_user_id(),
                            'settings_access_denied',
                            sprintf(
                                __('Access denied to %s settings due to missing MFA', 'wp-gdpr-framework'),
                                $setting_group
                            ),
                            'high'
                        );
                    }
                    
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /**
     * Generate a security status report
     * 
     * @return array Security status
     */
    public function getSecurityStatus() {
        $status = [
            'encryption' => [
                'enabled' => get_option('gdpr_enable_encryption', 1),
                'key_exists' => get_option('gdpr_encryption_key') ? true : false,
                'last_rotation' => get_option('gdpr_last_key_rotation', 0),
                'auto_rotation' => get_option('gdpr_auto_key_rotation', 0)
            ],
            'access_control' => [
                'rbac_available' => isset($this->components['rbac']),
                'mfa_available' => isset($this->components['mfa']),
                'admin_mfa_enabled' => isset($this->components['mfa']) && $this->components['mfa']->userHasMFA(get_current_user_id()),
                'session_duration' => get_option('gdpr_session_duration', 3600),
                'inactive_timeout' => get_option('gdpr_inactive_timeout', 900)
            ],
            'audit_logging' => [
                'enabled' => get_option('gdpr_audit_enabled', true),
                'tamper_protection' => get_option('gdpr_audit_tamper_protection', true),
                'retention_days' => get_option('gdpr_audit_retention_days', 365)
            ],
            'api_security' => [
                'enabled' => get_option('gdpr_api_enabled', 0),
                'whitelist_enabled' => !empty(get_option('gdpr_api_whitelist', '')),
                'require_2fa' => get_option('gdpr_api_require_2fa', 1),
                'enforce_tls' => get_option('gdpr_api_enforce_tls', 1)
            ],
            'enforcement_mode' => $this->enforcement_mode,
            'https_enabled' => is_ssl(),
            'security_score' => 0 // Calculated below
        ];
        
        // Calculate security score
        $score = 0;
        $total_points = 0;
        
        // Encryption (25 points)
        if ($status['encryption']['enabled']) $score += 10;
        if ($status['encryption']['key_exists']) $score += 10;
        if ($status['encryption']['last_rotation'] > 0) $score += 2;
        if ($status['encryption']['auto_rotation'] > 0) $score += 3;
        $total_points += 25;
        
        // Access Control (25 points)
        if ($status['access_control']['rbac_available']) $score += 8;
        if ($status['access_control']['mfa_available']) $score += 8;
        if ($status['access_control']['admin_mfa_enabled']) $score += 9;
        $total_points += 25;
        
        // Audit Logging (20 points)
        if ($status['audit_logging']['enabled']) $score += 10;
        if ($status['audit_logging']['tamper_protection']) $score += 10;
        $total_points += 20;
        
        // API Security (15 points)
        if (!$status['api_security']['enabled']) {
            // If API is disabled, give full points since it's not a security risk
            $score += 15;
        } else {
            // If API is enabled, check security measures
            if ($status['api_security']['whitelist_enabled']) $score += 5;
            if ($status['api_security']['require_2fa']) $score += 5;
            if ($status['api_security']['enforce_tls']) $score += 5;
        }
        $total_points += 15;
        
        // HTTPS (15 points)
        if ($status['https_enabled']) $score += 15;
        $total_points += 15;
        
        // Calculate final score as percentage
        $status['security_score'] = round(($score / $total_points) * 100);
        
        return $status;
    }
}
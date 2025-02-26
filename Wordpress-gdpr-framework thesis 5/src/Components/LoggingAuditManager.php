<?php
namespace GDPRFramework\Components;

/**
 * Tamper-Proof Audit Logging Manager
 * 
 * Implements a cryptographically secured audit logging system as specified in the
 * security implementation chapter:
 * - SHA-512 cryptographic hashing
 * - Immutable log records
 * - Integrity verification
 * - Automated log rotation
 * - Anomaly detection alerts
 */
class LoggingAuditManager {
    private $db;
    private $settings;
    private $table_name;
    private $debug = false;
    private $tamper_protection_enabled = true;
    private $retention_days = 365; // Default: 1 year
    private $severity_levels = ['low', 'medium', 'high'];
    private $integrity_salt;

    /**
     * Constructor
     * 
     * @param object $database Database instance
     * @param object $settings Settings instance
     */
    public function __construct($database, $settings) {
        global $wpdb;
        $this->db = $database;
        $this->settings = $settings;
        $this->table_name = $wpdb->prefix . 'gdpr_audit_log';
        
        // Load settings
        $this->tamper_protection_enabled = get_option('gdpr_enable_tamper_protection', 1);
        $this->retention_days = get_option('gdpr_audit_retention_days', 365);
        $this->debug = defined('WP_DEBUG') && WP_DEBUG;
        
        // Initialize integrity salt - unique to each installation
        $this->initializeIntegritySalt();
        
        // Initialize hooks
        $this->initializeHooks();
        
        // Verify table exists
        $this->verifyTable();
    }

    /**
     * Initialize integrity salt for tamper protection
     */
    private function initializeIntegritySalt() {
        $salt = get_option('gdpr_audit_integrity_salt');
        
        if (!$salt) {
            // Generate a strong random salt
            if (function_exists('random_bytes')) {
                $salt = bin2hex(random_bytes(32));
            } elseif (function_exists('openssl_random_pseudo_bytes')) {
                $salt = bin2hex(openssl_random_pseudo_bytes(32));
            } else {
                // Fallback to less secure but still usable method
                $salt = wp_generate_password(64, true, true);
            }
            
            update_option('gdpr_audit_integrity_salt', $salt);
        }
        
        $this->integrity_salt = $salt;
    }

    /**
     * Initialize WordPress hooks
     */
    private function initializeHooks() {
        // Admin settings
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('admin_init', [$this, 'addCustomCapabilities']);
        add_action('admin_init', [$this, 'verifyLogIntegrity']);
        
        // Register export and cleanup actions
        add_action('admin_post_gdpr_export_audit_log', [$this, 'handleExport']);
        add_action('admin_post_gdpr_verify_audit_log', [$this, 'handleVerifyIntegrity']);
        add_action('admin_post_gdpr_clear_audit_log', [$this, 'handleClearAuditLog']);
        
        // Register shortcodes
        add_action('init', [$this, 'registerShortcodes']);
        
        // User activity tracking hooks
        $this->registerUserActivityTracking();
    }

    /**
     * Register hooks for tracking user activity
     */
    private function registerUserActivityTracking() {
        // User authentication events
        add_action('wp_login', [$this, 'logUserLogin'], 10, 2);
        add_action('wp_logout', [$this, 'logUserLogout']);
        add_action('wp_login_failed', [$this, 'logLoginFailed']);
        add_action('user_register', [$this, 'logUserRegistration']);
        
        // Password events
        add_action('after_password_reset', [$this, 'logPasswordReset']);
        add_action('retrieve_password', [$this, 'logPasswordRetrievalRequest']);
        
        // User management events
        add_action('profile_update', [$this, 'logProfileUpdate'], 10, 2);
        add_action('set_user_role', [$this, 'logRoleChange'], 10, 3);
        add_action('delete_user', [$this, 'logUserDeletion']);
        
        // GDPR-specific events
        add_action('gdpr_consent_updated', [$this, 'logConsentUpdate'], 10, 3);
        add_action('gdpr_consent_recorded', [$this, 'logConsentRecord'], 10, 3);
        add_action('gdpr_consent_update_failed', [$this, 'logConsentUpdateFailure'], 10, 3);
        add_action('gdpr_data_exported', [$this, 'logDataExport'], 10, 2);
        add_action('gdpr_data_erased', [$this, 'logDataErasure'], 10, 2);
        add_action('gdpr_key_rotated', [$this, 'logKeyRotation'], 10, 2);
        add_action('gdpr_key_rotation_failed', [$this, 'logKeyRotationFailure'], 10, 2);
        add_action('gdpr_data_reencrypted', [$this, 'logDataReencryption'], 10, 1);
        add_action('gdpr_data_reencryption_failed', [$this, 'logDataReencryptionFailure'], 10, 2);
        
        // Access control and security events
        add_action('gdpr_successful_login', [$this, 'logSuccessfulLogin'], 10, 1);
        add_action('gdpr_failed_login', [$this, 'logFailedLogin'], 10, 2);
        add_action('gdpr_account_locked', [$this, 'logAccountLockout'], 10, 2);
        add_action('gdpr_login_blocked', [$this, 'logLoginBlocked'], 10, 2);
        add_action('gdpr_api_authenticated', [$this, 'logAPIAuthentication'], 10, 1);
        add_action('gdpr_mfa_success', [$this, 'logMFASuccess'], 10, 1);
        add_action('gdpr_mfa_failed', [$this, 'logMFAFailed'], 10, 2);
    }

    /**
     * Verify audit log table exists and has correct structure
     */
    private function verifyTable() {
        try {
            $table_exists = $this->db->query(
                "SHOW TABLES LIKE '{$this->table_name}'"
            );

            if (empty($table_exists)) {
                // Create table if it doesn't exist
                $this->createTable();
            } else {
                // Verify table structure
                $columns = $this->db->query("DESCRIBE {$this->table_name}");
                $required_columns = [
                    'id', 'user_id', 'action', 'details', 'severity', 
                    'ip_address', 'user_agent', 'timestamp'
                ];
                
                // Check if we need to add integrity_hash column for tamper-proof logs
                $has_integrity_hash = false;

                $existing_columns = array_map(function($col) use (&$has_integrity_hash) {
                    if ($col->Field === 'integrity_hash') {
                        $has_integrity_hash = true;
                    }
                    return $col->Field;
                }, $columns);

                // Add integrity_hash column if it doesn't exist
                if (!$has_integrity_hash && $this->tamper_protection_enabled) {
                    $this->addIntegrityHashColumn();
                }

                $missing_columns = array_diff($required_columns, $existing_columns);

                if (!empty($missing_columns)) {
                    // Update table structure if needed
                    $this->updateTable($missing_columns);
                }
            }

            // Create indexes for performance optimization
            $this->createIndexes();

            if ($this->debug) {
                error_log("GDPR Audit: Table verification successful - {$this->table_name}");
            }

        } catch (\Exception $e) {
            error_log("GDPR Audit Error: " . $e->getMessage());
            if ($this->debug) {
                add_action('admin_notices', function() use ($e) {
                    echo '<div class="notice notice-error"><p>GDPR Audit Error: ' . 
                         esc_html($e->getMessage()) . '</p></div>';
                });
            }
        }
    }

    /**
     * Create audit log table
     */
    private function createTable() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned DEFAULT NULL,
            action varchar(100) NOT NULL,
            details text DEFAULT NULL,
            severity enum('low', 'medium', 'high') DEFAULT 'low',
            ip_address varchar(45) DEFAULT NULL,
            user_agent text DEFAULT NULL,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP,
            integrity_hash varchar(128) DEFAULT NULL,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY action (action),
            KEY severity (severity),
            KEY timestamp (timestamp)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    /**
     * Update table to add missing columns
     */
    private function updateTable($missing_columns) {
        global $wpdb;
        
        foreach ($missing_columns as $column) {
            switch ($column) {
                case 'integrity_hash':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN integrity_hash VARCHAR(128) AFTER timestamp");
                    break;
                case 'user_id':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN user_id bigint(20) unsigned DEFAULT NULL AFTER id");
                    break;
                case 'action':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN action varchar(100) NOT NULL AFTER user_id");
                    break;
                case 'details':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN details text DEFAULT NULL AFTER action");
                    break;
                case 'severity':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN severity enum('low', 'medium', 'high') DEFAULT 'low' AFTER details");
                    break;
                case 'ip_address':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN ip_address varchar(45) DEFAULT NULL AFTER severity");
                    break;
                case 'user_agent':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN user_agent text DEFAULT NULL AFTER ip_address");
                    break;
                case 'timestamp':
                    $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN timestamp datetime DEFAULT CURRENT_TIMESTAMP AFTER user_agent");
                    break;
            }
        }
    }

    /**
     * Add integrity_hash column to audit log table for tamper-proof logging
     */
    private function addIntegrityHashColumn() {
        global $wpdb;
        
        try {
            $wpdb->query("ALTER TABLE {$this->table_name} ADD COLUMN integrity_hash VARCHAR(128) AFTER timestamp");
            
            if ($this->debug) {
                error_log("GDPR Audit: Added integrity_hash column to audit log table");
            }
            
            // Generate hashes for existing records
            $this->generateIntegrityHashes();
            
        } catch (\Exception $e) {
            error_log("GDPR Audit Error: Failed to add integrity_hash column - " . $e->getMessage());
        }
    }

    /**
     * Create indexes for performance optimization
     */
    private function createIndexes() {
        global $wpdb;
        
        // Check for required indexes
        $indexes = $wpdb->get_results("SHOW INDEX FROM {$this->table_name}");
        $existing_indexes = [];
        
        foreach ($indexes as $index) {
            $existing_indexes[] = $index->Key_name;
        }
        
        // Define indexes to create
        $required_indexes = [
            'user_timestamp' => 'user_id, timestamp',
            'severity_timestamp' => 'severity, timestamp'
        ];
        
        // Create missing indexes
        foreach ($required_indexes as $name => $columns) {
            if (!in_array($name, $existing_indexes)) {
                $wpdb->query("CREATE INDEX {$name} ON {$this->table_name} ({$columns})");
                
                if ($wpdb->last_error) {
                    error_log("GDPR Audit - Failed to create index {$name} on {$this->table_name}: " . $wpdb->last_error);
                }
            }
        }
    }

    /**
     * Generate integrity hashes for existing audit log entries
     */
    private function generateIntegrityHashes() {
        global $wpdb;
        
        try {
            $logs = $wpdb->get_results("SELECT * FROM {$this->table_name} WHERE integrity_hash IS NULL OR integrity_hash = ''");
            
            foreach ($logs as $log) {
                $hash = $this->generateIntegrityHash($log);
                
                $wpdb->update(
                    $this->table_name,
                    ['integrity_hash' => $hash],
                    ['id' => $log->id]
                );
            }
            
            if ($this->debug) {
                error_log("GDPR Audit: Generated integrity hashes for " . count($logs) . " existing records");
            }
            
        } catch (\Exception $e) {
            error_log("GDPR Audit Error: Failed to generate integrity hashes - " . $e->getMessage());
        }
    }

    /**
     * Register settings for the audit log
     */
    public function registerSettings() {
        register_setting('gdpr_framework_settings', 'gdpr_audit_retention_days', [
            'type' => 'integer',
            'default' => 365,
            'sanitize_callback' => [$this, 'sanitizeRetentionDays']
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_enable_tamper_protection', [
            'type' => 'boolean',
            'default' => 1,
            'sanitize_callback' => 'absint'
        ]);

        register_setting('gdpr_framework_settings', 'gdpr_audit_alert_threshold', [
            'type' => 'integer',
            'default' => 5,
            'sanitize_callback' => 'absint'
        ]);

        // Add settings section
        add_settings_section(
            'gdpr_audit_section',
            __('Audit Logging Settings', 'wp-gdpr-framework'),
            [$this, 'renderAuditSection'],
            'gdpr_framework_settings'
        );
        
        // Add settings fields
        add_settings_field(
            'gdpr_enable_tamper_protection',
            __('Tamper-Proof Logging', 'wp-gdpr-framework'),
            [$this, 'renderTamperProtectionField'],
            'gdpr_framework_settings',
            'gdpr_audit_section'
        );
        
        add_settings_field(
            'gdpr_audit_retention_days',
            __('Log Retention Period', 'wp-gdpr-framework'),
            [$this, 'renderRetentionDaysField'],
            'gdpr_framework_settings',
            'gdpr_audit_section'
        );
        
        add_settings_field(
            'gdpr_audit_alert_threshold',
            __('Anomaly Alert Threshold', 'wp-gdpr-framework'),
            [$this, 'renderAlertThresholdField'],
            'gdpr_framework_settings',
            'gdpr_audit_section'
        );
    }

    /**
     * Add custom capabilities for GDPR officers
     */
    public function addCustomCapabilities() {
        $roles = ['administrator', 'editor']; // Add roles that should have access
        foreach ($roles as $role_name) {
            $role = get_role($role_name);
            if ($role) {
                $role->add_cap('view_gdpr_audit_log');
            }
        }
    }

    /**
     * Sanitize retention days setting
     */
    public function sanitizeRetentionDays($days) {
        $days = absint($days);
        return $days < 30 ? 30 : $days;
    }

    /**
     * Render audit section description
     */
    public function renderAuditSection() {
        echo '<p>' . 
             esc_html__('Configure the audit logging system for tracking GDPR-related activities.', 'wp-gdpr-framework') . 
             '</p>';
    }

    /**
     * Render tamper protection field
     */
    public function renderTamperProtectionField() {
        $enabled = get_option('gdpr_enable_tamper_protection', 1);
        
        echo '<input type="checkbox" id="gdpr_enable_tamper_protection" name="gdpr_enable_tamper_protection" value="1" ' . 
             checked($enabled, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Enable cryptographic tamper protection for log entries using SHA-512 hashing.', 'wp-gdpr-framework') . 
             '</p>';
    }

    /**
     * Render retention days field
     */
    public function renderRetentionDaysField() {
        $days = get_option('gdpr_audit_retention_days', 365);
        
        echo '<input type="number" id="gdpr_audit_retention_days" name="gdpr_audit_retention_days" value="' . 
             esc_attr($days) . '" min="30" class="small-text"> ' . 
             esc_html__('days', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('Number of days to retain audit logs before automatic deletion. Minimum: 30 days.', 'wp-gdpr-framework') . 
             '</p>';
    }

    /**
     * Render alert threshold field
     */
    public function renderAlertThresholdField() {
        $threshold = get_option('gdpr_audit_alert_threshold', 5);
        
        echo '<input type="number" id="gdpr_audit_alert_threshold" name="gdpr_audit_alert_threshold" value="' . 
             esc_attr($threshold) . '" min="1" class="small-text">';
             
        echo '<p class="description">' . 
             esc_html__('Number of high-severity events within an hour to trigger an anomaly alert.', 'wp-gdpr-framework') . 
             '</p>';
    }

    /**
     * Generate SHA-512 integrity hash for a log entry
     */
    private function generateIntegrityHash($log) {
        $data = $log->id . '|' . 
                $log->user_id . '|' . 
                $log->action . '|' . 
                $log->details . '|' . 
                $log->severity . '|' . 
                $log->ip_address . '|' . 
                $log->user_agent . '|' . 
                $log->timestamp;
                
        // Add installation-specific salt to prevent rainbow table attacks
        $data .= '|' . $this->integrity_salt;
        
        // Generate SHA-512 hash
        return hash('sha512', $data);
    }

    /**
     * Verify integrity of audit logs
     */
    public function verifyLogIntegrity() {
        // Only run on audit log page or when explicitly requested
        if (!isset($_GET['page']) || $_GET['page'] !== 'gdpr-framework-audit') {
            return;
        }
        
        // Check if tamper protection is enabled
        if (!$this->tamper_protection_enabled) {
            return;
        }
        
        // Check if verification was requested
        $verify = isset($_GET['verify']) && $_GET['verify'] === '1';
        
        if ($verify) {
            $result = $this->performIntegrityCheck();
            
            if ($result['tampered_logs'] > 0) {
                // Log the tampering detection
                $this->log(
                    get_current_user_id(),
                    'integrity_check_failed',
                    sprintf(__('Tampered logs detected: %d', 'wp-gdpr-framework'), $result['tampered_logs']),
                    'high'
                );
                
                // Add admin notice
                add_action('admin_notices', function() use ($result) {
                    echo '<div class="notice notice-error">';
                    echo '<p><strong>' . esc_html__('SECURITY ALERT: Log tampering detected!', 'wp-gdpr-framework') . '</strong></p>';
                    echo '<p>' . sprintf(
                        esc_html__('Found %d tampered log entries out of %d checked. This may indicate a security breach.', 'wp-gdpr-framework'),
                        $result['tampered_logs'],
                        $result['checked_logs']
                    ) . '</p>';
                    echo '<p>' . esc_html__('Please review your security measures immediately.', 'wp-gdpr-framework') . '</p>';
                    echo '</div>';
                });
            } else {
                // Log the successful verification
                $this->log(
                    get_current_user_id(),
                    'integrity_check_passed',
                    sprintf(__('Integrity check passed: %d logs verified', 'wp-gdpr-framework'), $result['checked_logs']),
                    'low'
                );
                
                // Add admin notice
                add_action('admin_notices', function() use ($result) {
                    echo '<div class="notice notice-success is-dismissible">';
                    echo '<p>' . sprintf(
                        esc_html__('Log integrity verification passed: %d logs verified', 'wp-gdpr-framework'),
                        $result['checked_logs']
                    ) . '</p>';
                    echo '</div>';
                });
            }
        }
    }

    /**
     * Perform integrity check on logs
     */
    private function performIntegrityCheck() {
        global $wpdb;
        
        $result = [
            'checked_logs' => 0,
            'tampered_logs' => 0,
            'tampered_ids' => []
        ];
        
        // Get logs with integrity hashes
        $logs = $wpdb->get_results("SELECT * FROM {$this->table_name} WHERE integrity_hash IS NOT NULL");
        
        foreach ($logs as $log) {
            $result['checked_logs']++;
            
            // Generate expected hash
            $expected_hash = $this->generateIntegrityHash($log);
            
            // Compare with stored hash
            if ($expected_hash !== $log->integrity_hash) {
                $result['tampered_logs']++;
                $result['tampered_ids'][] = $log->id;
            }
        }
        
        return $result;
    }

    /**
     * Handle integrity verification request
     */
    public function handleVerifyIntegrity() {
        check_admin_referer('gdpr_verify_audit_log');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to perform this action.', 'wp-gdpr-framework'));
        }
        
        // Redirect to audit log page with verify parameter
        wp_safe_redirect(add_query_arg([
            'page' => 'gdpr-framework-audit',
            'verify' => '1'
        ], admin_url('admin.php')));
        exit;
    }

    /**
     * Log an event to the audit log
     * 
     * @param int $user_id User ID (0 for system actions)
     * @param string $action Action name
     * @param string $details Action details
     * @param string $severity Severity level (low, medium, high)
     * @param string $ip_address Optional IP address (will be detected if not provided)
     * @return bool Success status
     */
    public function log($user_id, $action, $details = '', $severity = 'low', $ip_address = '') {
        try {
            if (empty($ip_address)) {
                $ip_address = $this->getClientIP();
            }

            $data = [
                'user_id' => $user_id,
                'action' => $this->sanitizeAction($action),
                'details' => $this->filterSensitiveData($details),
                'severity' => $this->validateSeverity($severity),
                'ip_address' => $this->anonymizeIP($ip_address),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? 
                    substr(sanitize_text_field($_SERVER['HTTP_USER_AGENT']), 0, 255) : '',
                'timestamp' => current_time('mysql')
            ];

            if ($this->debug) {
                error_log("GDPR Audit: Attempting to log entry - " . wp_json_encode($data));
            }

            // Start transaction for data integrity
            global $wpdb;
            $wpdb->query('START TRANSACTION');

            $result = $this->db->insert(
                'audit_log',
                $data,
                ['%d', '%s', '%s', '%s', '%s', '%s', '%s']
            );

            if ($result === false) {
                throw new \Exception($this->db->get_last_error());
            }
            
            $log_id = $this->db->insert_id;
            
            // Add integrity hash for tamper-proof logging if enabled
            if ($this->tamper_protection_enabled) {
                // Create a temporary log object
                $log = (object)$data;
                $log->id = $log_id;
                
                // Generate SHA-512 hash
                $integrity_hash = $this->generateIntegrityHash($log);
                
                // Update the record with the hash
                $wpdb->update(
                    $this->table_name,
                    ['integrity_hash' => $integrity_hash],
                    ['id' => $log_id]
                );
            }
            
            $wpdb->query('COMMIT');

            if ($this->debug) {
                error_log("GDPR Audit: Entry logged successfully - ID: " . $log_id);
            }

            // Check for potential anomalies if high severity
            if ($severity === 'high') {
                $this->checkForAnomalies($action);
            }

            return true;

        } catch (\Exception $e) {
            global $wpdb;
            $wpdb->query('ROLLBACK');
            
            error_log("GDPR Audit Error: Failed to log entry - " . $e->getMessage());
            if ($this->debug) {
                add_action('admin_notices', function() use ($e) {
                    echo '<div class="notice notice-error"><p>GDPR Audit Error: ' . 
                         esc_html($e->getMessage()) . '</p></div>';
                });
            }
            return false;
        }
    }

    /**
     * Check for anomalies in audit logs
     */
    private function checkForAnomalies($action) {
        global $wpdb;
        
        // Get threshold from settings
        $threshold = get_option('gdpr_audit_alert_threshold', 5);
        
        // Get IP address
        $ip_address = $this->getClientIP();
        
        // Check for high-severity events in the last hour
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table_name} 
             WHERE severity = 'high' 
             AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
        ));
        
        if ($count >= $threshold) {
            // Log the anomaly
            $this->log(
                0,
                'security_anomaly',
                sprintf(
                    __('Security anomaly detected: %d high-severity events in the last hour.', 'wp-gdpr-framework'),
                    $count
                ),
                'high'
            );
            
            // Send alert email if enabled
            $this->sendAnomalyAlert('security_anomaly', [
                'count' => $count,
                'action' => $action,
                'ip_address' => $ip_address
            ]);
        }
    }

    /**
     * Send anomaly alert email
     */
    private function sendAnomalyAlert($type, $data) {
        $admin_email = get_option('admin_email');
        
        // Check if the DPO email is set, use that instead
        $dpo_email = get_option('gdpr_dpo_email');
        if (!empty($dpo_email)) {
            $admin_email = $dpo_email;
        }
        
        $subject = sprintf(
            __('[SECURITY ALERT] %s detected on %s', 'wp-gdpr-framework'),
            ucfirst(str_replace('_', ' ', $type)),
            get_bloginfo('name')
        );
        
        $message = '';
        
        switch ($type) {
            case 'security_anomaly':
                $message = sprintf(
                    __('Security anomaly detected on your website.

Details:
- Timestamp: %s
- High-severity events: %d within the last hour
- Triggering action: %s
- IP Address: %s

This may indicate a security breach attempt. Please review your audit logs immediately.', 'wp-gdpr-framework'),
                    current_time('mysql'),
                    $data['count'],
                    $data['action'],
                    $data['ip_address']
                );
                break;
                
            case 'integrity_anomaly':
                $message = sprintf(
                    __('Audit log tampering detected on your website.

Details:
- Timestamp: %s
- Detected by: %s
- Tampered logs: %d out of %d checked

This indicates that someone may have modified the audit logs. This is a serious security concern and should be investigated immediately.', 'wp-gdpr-framework'),
                    current_time('mysql'),
                    $data['detected_by'],
                    $data['tampered_logs'],
                    $data['checked_logs']
                );
                break;
                
            default:
                $message = sprintf(
                    __('Security alert detected on your website.

Details:
- Type: %s
- Timestamp: %s

Please check your audit logs for more information.', 'wp-gdpr-framework'),
                    $type,
                    current_time('mysql')
                );
        }
        
        // Add site info
        $message .= "\n\n" . sprintf(
            __('Site URL: %s', 'wp-gdpr-framework'),
            get_bloginfo('url')
        );
        
        // Send email
        wp_mail($admin_email, $subject, $message);
    }

    /**
     * Handle audit log export
     */
    public function handleExport() {
        check_admin_referer('gdpr_export_audit_log');
        
        if (!current_user_can('view_gdpr_audit_log')) {
            wp_die(__('You do not have permission to export audit logs.', 'wp-gdpr-framework'));
        }
        
        // Get filter parameters
        $filters = [
            'user_id' => isset($_GET['user_id']) ? absint($_GET['user_id']) : null,
            'severity' => isset($_GET['severity']) ? sanitize_text_field($_GET['severity']) : null,
            'from_date' => isset($_GET['from_date']) ? sanitize_text_field($_GET['from_date']) : null,
            'to_date' => isset($_GET['to_date']) ? sanitize_text_field($_GET['to_date']) : null,
            'action' => isset($_GET['action_type']) ? sanitize_text_field($_GET['action_type']) : null
        ];
        
        // Get export format
        $format = isset($_GET['format']) ? sanitize_text_field($_GET['format']) : 'csv';
        
        // Export the logs
        $this->exportLogs($filters, $format);
        exit;
    }

    /**
     * Export logs to file
     */
    private function exportLogs($filters = [], $format = 'csv') {
        if (!current_user_can('view_gdpr_audit_log')) {
            return false;
        }
        
        $result = $this->getAuditLog($filters);
        $logs = $result['logs'];
        
        // Generate filename
        $filename = 'gdpr-audit-log-' . date('Y-m-d-H-i-s');
        
        switch ($format) {
            case 'json':
                // Set headers for JSON download
                header('Content-Type: application/json; charset=utf-8');
                header('Content-Disposition: attachment; filename="' . $filename . '.json"');
                
                // Add metadata
                $data = [
                    'metadata' => [
                        'exported_at' => date('c'),
                        'exported_by' => get_current_user_id(),
                        'total_logs' => count($logs),
                        'filters' => $filters
                    ],
                    'logs' => $logs
                ];
                
                // Output JSON
                echo json_encode($data, JSON_PRETTY_PRINT);
                break;
                
            case 'xml':
                // Set headers for XML download
                header('Content-Type: application/xml; charset=utf-8');
                header('Content-Disposition: attachment; filename="' . $filename . '.xml"');
                
                // Create XML document
                $xml = new \SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><audit_log></audit_log>');
                
                // Add metadata
                $metadata = $xml->addChild('metadata');
                $metadata->addChild('exported_at', date('c'));
                $metadata->addChild('exported_by', get_current_user_id());
                $metadata->addChild('total_logs', count($logs));
                
                // Add filters
                $filters_xml = $metadata->addChild('filters');
                foreach ($filters as $key => $value) {
                    if ($value !== null) {
                        $filters_xml->addChild($key, $value);
                    }
                }
                
                // Add logs
                foreach ($logs as $log) {
                    $log_xml = $xml->addChild('log');
                    
                    foreach (get_object_vars($log) as $key => $value) {
                        if ($value !== null) {
                            $log_xml->addChild($key, htmlspecialchars($value));
                        }
                    }
                }
                
                // Output XML
                echo $xml->asXML();
                break;
                
            case 'csv':
            default:
                // Set headers for CSV download
                header('Content-Type: text/csv; charset=utf-8');
                header('Content-Disposition: attachment; filename="' . $filename . '.csv"');
                
                $output = fopen('php://output', 'w');
                
                // Add UTF-8 BOM for proper Excel handling
                fputs($output, chr(0xEF) . chr(0xBB) . chr(0xBF));
                
                // Write headers
                fputcsv($output, [
                    __('ID', 'wp-gdpr-framework'),
                    __('Timestamp', 'wp-gdpr-framework'),
                    __('User', 'wp-gdpr-framework'),
                    __('Action', 'wp-gdpr-framework'),
                    __('Details', 'wp-gdpr-framework'),
                    __('Severity', 'wp-gdpr-framework'),
                    __('IP Address', 'wp-gdpr-framework'),
                    __('Integrity Verified', 'wp-gdpr-framework')
                ]);
                
                // Write data
                foreach ($logs as $log) {
                    $user_name = '';
                    if ($log->user_id) {
                        $user = get_userdata($log->user_id);
                        $user_name = $user ? $user->display_name : __('Deleted User', 'wp-gdpr-framework');
                    } else {
                        $user_name = __('System', 'wp-gdpr-framework');
                    }
                    
                    // Check integrity if tamper protection is enabled
                    $integrity_verified = __('Not Checked', 'wp-gdpr-framework');
                    if ($this->tamper_protection_enabled && !empty($log->integrity_hash)) {
                        $expected_hash = $this->generateIntegrityHash($log);
                        $integrity_verified = ($expected_hash === $log->integrity_hash) 
                            ? __('Yes', 'wp-gdpr-framework') 
                            : __('TAMPERED', 'wp-gdpr-framework');
                    }
                    
                    fputcsv($output, [
                        $log->id,
                        $log->timestamp,
                        $user_name,
                        $log->action,
                        $log->details,
                        $log->severity,
                        $log->ip_address,
                        $integrity_verified
                    ]);
                }
                
                fclose($output);
                break;
        }
        
        return true;
    }

    /**
     * Clear audit log
     */
    public function clearAuditLog() {
        try {
            // Before clearing, export logs to a backup file
            $this->backupLogsBeforeClear();
            
            global $wpdb;
            $wpdb->query("TRUNCATE TABLE {$this->table_name}");
            
            // Log that the audit log was cleared
            $this->log(
                get_current_user_id(),
                'audit_log_cleared',
                'Audit log was cleared manually by administrator',
                'high'
            );
            
            return true;
        } catch (\Exception $e) {
            error_log("GDPR Audit Error: Failed to clear audit log - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Create a backup of logs before clearing
     */
    private function backupLogsBeforeClear() {
        try {
            global $wpdb;
            
            // Get all logs
            $logs = $wpdb->get_results("SELECT * FROM {$this->table_name}");
            
            if (empty($logs)) {
                return false; // No logs to backup
            }
            
            $upload_dir = wp_upload_dir();
            $backup_dir = $upload_dir['basedir'] . '/gdpr-backups';
            
            // Create backup directory if it doesn't exist
            if (!file_exists($backup_dir)) {
                wp_mkdir_p($backup_dir);
                
                // Add index.php to prevent directory listing
                file_put_contents($backup_dir . '/index.php', '<?php // Silence is golden');
                
                // Add .htaccess for extra security
                file_put_contents($backup_dir . '/.htaccess', 'deny from all');
            }
            
            // Generate backup filename with timestamp
            $filename = 'audit-log-backup-' . date('Y-m-d-H-i-s') . '.csv';
            $filepath = $backup_dir . '/' . $filename;
            
            $fp = fopen($filepath, 'w');
            
            // Add UTF-8 BOM for proper Excel handling
            fputs($fp, chr(0xEF) . chr(0xBB) . chr(0xBF));
            
            // Write headers
            fputcsv($fp, array_keys(get_object_vars($logs[0])));
            
            // Write data
            foreach ($logs as $log) {
                fputcsv($fp, get_object_vars($log));
            }
            
            fclose($fp);
            
            if ($this->debug) {
                error_log("GDPR Audit: Created backup file: " . $filepath);
            }
            
            return $filepath;
            
        } catch (\Exception $e) {
            error_log("GDPR Audit Error: Failed to create backup - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Handle clearing the audit log
     */
    public function handleClearAuditLog() {
        // Check if the clear action was triggered
        if (!isset($_POST['clear_audit_log'])) {
            return;
        }

        // Verify nonce and capabilities
        if (!isset($_POST['clear_audit_nonce']) || 
            !wp_verify_nonce($_POST['clear_audit_nonce'], 'gdpr_clear_audit_log')) {
            wp_die(__('Security check failed.', 'wp-gdpr-framework'));
        }

        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to perform this action.', 'wp-gdpr-framework'));
        }

        if ($this->clearAuditLog()) {
            // Redirect back with success message
            wp_redirect(add_query_arg([
                'page' => 'gdpr-framework-audit',
                'cleared' => '1'
            ], admin_url('admin.php')));
        } else {
            // Redirect back with error message
            wp_redirect(add_query_arg([
                'page' => 'gdpr-framework-audit',
                'cleared' => '0'
            ], admin_url('admin.php')));
        }
        exit;
    }

    /**
     * Register shortcode handler
     */
    public function registerShortcodes() {
        add_shortcode('gdpr_audit_log', [$this, 'renderAuditLogShortcode']);
    }

    /**
     * Render audit log shortcode
     */
    public function renderAuditLogShortcode($atts) {
        $atts = shortcode_atts([
            'view' => 'own',
            'limit' => 10,
            'page' => 1
        ], $atts);

        if (!$this->checkPermission(get_current_user_id())) {
            return '<p>' . __('You do not have permission to view audit logs.', 'wp-gdpr-framework') . '</p>';
        }

        $args = [
            'limit' => absint($atts['limit']),
            'offset' => (absint($atts['page']) - 1) * absint($atts['limit'])
        ];

        if ($atts['view'] !== 'all' || !current_user_can('view_gdpr_audit_log')) {
            $args['user_id'] = get_current_user_id();
        }

        $result = $this->getAuditLog($args);
        
        // Load template
        ob_start();
        include(GDPR_FRAMEWORK_TEMPLATE_PATH . 'public/audit-log.php');
        return ob_get_clean();
    }

    /**
     * Get audit log entries with filtering
     */
    public function getAuditLog($args = []) {
        if ($this->debug) {
            error_log("GDPR Audit: Starting getAuditLog with args: " . wp_json_encode($args));
        }

        try {
            $defaults = [
                'user_id' => null,
                'action' => null,
                'severity' => null,
                'from_date' => null,
                'to_date' => null,
                'limit' => 50,
                'offset' => 0,
                'orderby' => 'timestamp',
                'order' => 'DESC'
            ];

            $args = wp_parse_args($args, $defaults);

            // Build query
            $where = [];
            $params = [];

            if (!empty($args['user_id'])) {
                $where[] = 'user_id = %d';
                $params[] = $args['user_id'];
            }

            if (!empty($args['severity'])) {
                $where[] = 'severity = %s';
                $params[] = $args['severity'];
            }

            if (!empty($args['from_date'])) {
                $where[] = 'timestamp >= %s';
                $params[] = $args['from_date'];
            }

            if (!empty($args['to_date'])) {
                $where[] = 'timestamp <= %s';
                $params[] = $args['to_date'];
            }

            if (!empty($args['action'])) {
                $where[] = 'action = %s';
                $params[] = $args['action'];
            }

            $query = "SELECT SQL_CALC_FOUND_ROWS l.*, u.display_name 
                     FROM {$this->table_name} l 
                     LEFT JOIN {$this->db->get_prefix()}users u ON l.user_id = u.ID";

            if (!empty($where)) {
                $query .= ' WHERE ' . implode(' AND ', $where);
            }

            $query .= " ORDER BY {$args['orderby']} {$args['order']}";
            
            if (!empty($args['limit'])) {
                $query .= ' LIMIT %d OFFSET %d';
                array_push($params, $args['limit'], $args['offset']);
            }

            $logs = $this->db->get_results(
                !empty($params) ? $this->db->prepare($query, $params) : $query
            );

            $total = $this->db->get_var('SELECT FOUND_ROWS()');
            
            // If tamper protection is enabled, verify log integrity
            if ($this->tamper_protection_enabled) {
                $this->verifyBatchIntegrity($logs);
            }

            return [
                'logs' => $logs,
                'total' => (int)$total,
                'pages' => ceil($total / max(1, $args['limit']))
            ];

        } catch (\Exception $e) {
            error_log("GDPR Audit Error: Failed to retrieve logs - " . $e->getMessage());
            return ['logs' => [], 'total' => 0, 'pages' => 0];
        }
    }

    /**
     * Verify integrity of a batch of logs
     */
    private function verifyBatchIntegrity($logs) {
        if (empty($logs)) {
            return;
        }
        
        $tampered_logs = [];
        
        foreach ($logs as $log) {
            if (isset($log->integrity_hash) && !empty($log->integrity_hash)) {
                $calculated_hash = $this->generateIntegrityHash($log);
                
                if ($calculated_hash !== $log->integrity_hash) {
                    $tampered_logs[] = $log->id;
                    
                    // Mark the log as potentially tampered
                    $log->tampered = true;
                }
            }
        }
        
        if (!empty($tampered_logs) && $this->debug) {
            error_log("GDPR Audit: Potential tampering detected in logs: " . implode(', ', $tampered_logs));
        }
    }

    /**
     * Check if user has permission to view audit logs
     */
    private function checkPermission($user_id = null) {
        if (!is_user_logged_in()) {
            return false;
        }
        
        if (current_user_can('view_gdpr_audit_log')) {
            return true;
        }
        
        return $user_id && $user_id === get_current_user_id();
    }

    /**
     * Get recent activities for dashboard
     */
    public function getRecentActivities($limit = 5) {
        return $this->db->get_results($this->db->prepare(
            "SELECT l.*, u.display_name 
             FROM {$this->table_name} l 
             LEFT JOIN {$this->db->get_prefix()}users u ON l.user_id = u.ID 
             ORDER BY timestamp DESC 
             LIMIT %d",
            $limit
        ));
    }

    /**
     * Get audit log statistics
     */
    public function getStats() {
        $stats = [
            'total_entries' => 0,
            'by_severity' => [
                'low' => 0,
                'medium' => 0,
                'high' => 0
            ],
            'recent_high_severity' => [],
            'tampering_detected' => false
        ];

        // Get total entries
        $stats['total_entries'] = $this->db->get_var(
            "SELECT COUNT(*) FROM {$this->table_name}"
        );

        // Get counts by severity
        $severity_counts = $this->db->get_results(
            "SELECT severity, COUNT(*) as count 
             FROM {$this->table_name} 
             GROUP BY severity"
        );

        foreach ($severity_counts as $count) {
            $stats['by_severity'][$count->severity] = (int)$count->count;
        }

        // Get recent high severity events
        $stats['recent_high_severity'] = $this->db->get_results(
            "SELECT * FROM {$this->table_name} 
             WHERE severity = 'high' 
             ORDER BY timestamp DESC 
             LIMIT 5"
        );
        
        // Check for evidence of tampering if tamper protection is enabled
        if ($this->tamper_protection_enabled) {
            $logs_with_hashes = $this->db->get_results(
                "SELECT * FROM {$this->table_name} 
                 WHERE integrity_hash IS NOT NULL 
                 ORDER BY id DESC 
                 LIMIT 100"
            );
            
            foreach ($logs_with_hashes as $log) {
                $calculated_hash = $this->generateIntegrityHash($log);
                
                if ($calculated_hash !== $log->integrity_hash) {
                    $stats['tampering_detected'] = true;
                    break;
                }
            }
        }

        return $stats;
    }

    /**
     * Clean up old audit logs
     */
    public function cleanupOldLogs() {
        $retention_days = get_option('gdpr_audit_retention_days', 365);
        
        // Before cleanup, export logs that will be deleted to a backup file
        $this->backupOldLogs($retention_days);
        
        return $this->db->query($this->db->prepare(
            "DELETE FROM {$this->table_name} 
             WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $retention_days
        ));
    }

    /**
     * Backup old logs before cleanup
     */
    private function backupOldLogs($retention_days) {
        try {
            global $wpdb;
            
            // Check if there are any logs to backup
            $count = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name} 
                 WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
                $retention_days
            ));
            
            if (empty($count) || $count == 0) {
                return false; // No logs to backup
            }
            
            $upload_dir = wp_upload_dir();
            $backup_dir = $upload_dir['basedir'] . '/gdpr-backups';
            
            // Create backup directory if it doesn't exist
            if (!file_exists($backup_dir)) {
                wp_mkdir_p($backup_dir);
                file_put_contents($backup_dir . '/index.php', '<?php // Silence is golden');
                file_put_contents($backup_dir . '/.htaccess', 'deny from all');
            }
            
            // Generate backup filename with timestamp
            $filename = 'old-logs-backup-' . date('Y-m-d') . '.csv';
            $filepath = $backup_dir . '/' . $filename;
            
            // Export old logs to CSV
            $logs = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM {$this->table_name} 
                 WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
                $retention_days
            ));
            
            $fp = fopen($filepath, 'w');
            
            // Add UTF-8 BOM for proper Excel handling
            fputs($fp, chr(0xEF) . chr(0xBB) . chr(0xBF));
            
            // Write headers
            fputcsv($fp, array_keys(get_object_vars($logs[0])));
            
            // Write data
            foreach ($logs as $log) {
                fputcsv($fp, get_object_vars($log));
            }
            
            fclose($fp);
            
            if ($this->debug) {
                error_log("GDPR Audit: Backed up " . count($logs) . " old logs to " . $filepath);
            }
            
            return $filepath;
            
        } catch (\Exception $e) {
            error_log("GDPR Audit Error: Failed to backup old logs - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Event logging methods for specific events
     */
    public function logUserLogin($username, $user) {
        if (!$user instanceof \WP_User) {
            return;
        }
        
        $this->log(
            $user->ID,
            'user_login',
            sprintf(__('User logged in: %s', 'wp-gdpr-framework'), $username),
            'low'
        );
    }
    
    public function logUserLogout() {
        $user_id = get_current_user_id();
        
        if (!$user_id) {
            return;
        }
        
        $this->log(
            $user_id,
            'user_logout',
            __('User logged out', 'wp-gdpr-framework'),
            'low'
        );
    }
    
    public function logLoginFailed($username) {
        // Try to get user ID if the username exists
        $user = get_user_by('login', $username);
        $user_id = $user ? $user->ID : 0;
        
        $this->log(
            $user_id,
            'login_failed',
            sprintf(__('Failed login attempt for username: %s', 'wp-gdpr-framework'), $username),
            'medium'
        );
        
        // Check for excessive failed login attempts
        $this->checkForLoginAnomaly($username);
    }
    
    /**
     * Check for login anomalies
     */
    private function checkForLoginAnomaly($username) {
        global $wpdb;
        
        // Get threshold from settings
        $threshold = get_option('gdpr_audit_alert_threshold', 5);
        
        // Get IP address
        $ip_address = $this->getClientIP();
        
        // Check for failed attempts from this IP in the last hour
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table_name} 
             WHERE action = 'login_failed' 
             AND ip_address = %s 
             AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
            $ip_address
        ));
        
        if ($count >= $threshold) {
            // Log the anomaly
            $this->log(
                0,
                'login_anomaly',
                sprintf(
                    __('Possible brute force attack detected. %d failed login attempts for username: %s from IP: %s', 'wp-gdpr-framework'),
                    $count,
                    $username,
                    $ip_address
                ),
                'high'
            );
            
            // Send alert email if enabled
            $this->sendAnomalyAlert('login_anomaly', [
                'username' => $username,
                'ip_address' => $ip_address,
                'attempts' => $count
            ]);
        }
    }
    
    public function logUserRegistration($user_id) {
        $user = get_userdata($user_id);
        
        if (!$user) {
            return;
        }
        
        $this->log(
            $user_id,
            'user_registration',
            sprintf(__('New user registered: %s', 'wp-gdpr-framework'), $user->user_login),
            'medium'
        );
    }
    
    public function logPasswordReset($user) {
        if (!$user instanceof \WP_User) {
            return;
        }
        
        $this->log(
            $user->ID,
            'password_reset',
            sprintf(__('Password reset for user: %s', 'wp-gdpr-framework'), $user->user_login),
            'medium'
        );
    }
    
    public function logPasswordRetrievalRequest($username) {
        $user = get_user_by('login', $username);
        
        if (!$user) {
            return;
        }
        
        $this->log(
            $user->ID,
            'password_retrieval_request',
            sprintf(__('Password retrieval requested for user: %s', 'wp-gdpr-framework'), $username),
            'medium'
        );
    }
    
    public function logProfileUpdate($user_id, $old_user_data) {
        $user = get_userdata($user_id);
        
        if (!$user) {
            return;
        }
        
        $this->log(
            $user_id,
            'profile_update',
            sprintf(__('Profile updated for user: %s', 'wp-gdpr-framework'), $user->user_login),
            'low'
        );
    }
    
    public function logRoleChange($user_id, $role, $old_roles) {
        $user = get_userdata($user_id);
        
        if (!$user) {
            return;
        }
        
        $this->log(
            $user_id,
            'role_change',
            sprintf(
                __('Role changed for user %s: from %s to %s', 'wp-gdpr-framework'),
                $user->user_login,
                implode(', ', $old_roles),
                $role
            ),
            'medium'
        );
    }
    
    public function logUserDeletion($user_id) {
        $user = get_userdata($user_id);
        
        if (!$user) {
            return;
        }
        
        $this->log(
            get_current_user_id(), // Who did the deletion
            'user_deletion',
            sprintf(__('User deleted: %s (ID: %d)', 'wp-gdpr-framework'), $user->user_login, $user_id),
            'high'
        );
    }
    
    public function logConsentUpdate($user_id, $consent_type, $status) {
        $status_text = $status ? __('granted', 'wp-gdpr-framework') : __('withdrawn', 'wp-gdpr-framework');
        
        $this->log(
            $user_id,
            'consent_update',
            sprintf(
                __('Consent for "%s" %s', 'wp-gdpr-framework'),
                $consent_type,
                $status_text
            ),
            'medium'
        );
    }
    
    public function logConsentRecord($user_id, $consent_type, $status) {
        $this->log(
            $user_id,
            'consent_recorded',
            sprintf(
                __('Consent recorded for %s: %s', 'wp-gdpr-framework'),
                $consent_type,
                $status ? __('Granted', 'wp-gdpr-framework') : __('Withdrawn', 'wp-gdpr-framework')
            ),
            'medium'
        );
    }
    
    public function logConsentUpdateFailure($user_id, $consent_type, $error) {
        $this->log(
            $user_id,
            'consent_update_failed',
            sprintf(
                __('Failed to update consent for %s: %s', 'wp-gdpr-framework'),
                $consent_type,
                $error
            ),
            'high'
        );
    }
    
    public function logDataExport($user_id, $request_id) {
        $this->log(
            $user_id,
            'data_export',
            sprintf(__('Data export completed for user ID: %d (Request ID: %d)', 'wp-gdpr-framework'), $user_id, $request_id),
            'medium'
        );
    }
    
    public function logDataErasure($user_id, $request_id) {
        $this->log(
            $user_id,
            'data_erasure',
            sprintf(__('Data erasure completed for user ID: %d (Request ID: %d)', 'wp-gdpr-framework'), $user_id, $request_id),
            'high'
        );
    }
    
    public function logKeyRotation($admin_id, $type = 'manual') {
        $this->log(
            $admin_id,
            'key_rotation',
            sprintf(__('Encryption key rotated (%s)', 'wp-gdpr-framework'), $type),
            'high'
        );
    }
    
    public function logKeyRotationFailure($admin_id, $error) {
        $this->log(
            $admin_id,
            'key_rotation_failed',
            sprintf(
                __('Key rotation failed: %s', 'wp-gdpr-framework'),
                $error
            ),
            'high'
        );
    }
    
    public function logDataReencryption($admin_id) {
        $this->log(
            $admin_id,
            'data_reencrypted',
            __('All sensitive data re-encrypted with new key', 'wp-gdpr-framework'),
            'high'
        );
    }
    
    public function logDataReencryptionFailure($admin_id, $error) {
        $this->log(
            $admin_id,
            'data_reencryption_failed',
            sprintf(
                __('Data re-encryption failed: %s', 'wp-gdpr-framework'),
                $error
            ),
            'high'
        );
    }
    
    public function logSuccessfulLogin($user_id) {
        $this->log(
            $user_id,
            'successful_login',
            __('Successful login', 'wp-gdpr-framework'),
            'low'
        );
    }
    
    public function logFailedLogin($user_id, $data) {
        $this->log(
            $user_id,
            'failed_login',
            sprintf(
                __('Failed login attempt from IP: %s, Username: %s', 'wp-gdpr-framework'),
                $data['ip_address'],
                $data['username']
            ),
            'medium',
            $data['ip_address']
        );
    }
    
    public function logAccountLockout($user_id, $data) {
        $this->log(
            $user_id,
            'account_lockout',
            sprintf(
                __('Account locked for %d minutes due to too many failed attempts', 'wp-gdpr-framework'),
                ceil($data['duration'] / 60)
            ),
            'high',
            $data['ip_address']
        );
    }
    
    public function logLoginBlocked($user_id, $data) {
        $this->log(
            $user_id,
            'login_blocked',
            sprintf(
                __('Login attempt blocked. Reason: %s', 'wp-gdpr-framework'),
                $data['reason']
            ),
            'medium',
            $data['ip_address']
        );
    }
    
    public function logAPIAuthentication($user_id) {
        $this->log(
            $user_id,
            'api_authentication',
            __('API authentication successful', 'wp-gdpr-framework'),
            'medium'
        );
    }
    
    public function logMFASuccess($user_id) {
        $this->log(
            $user_id,
            'mfa_success',
            __('Two-factor authentication successful', 'wp-gdpr-framework'),
            'low'
        );
    }
    
    public function logMFAFailed($user_id, $data) {
        $this->log(
            $user_id,
            'mfa_failed',
            sprintf(
                __('Two-factor authentication failed from IP: %s', 'wp-gdpr-framework'),
                $data['ip_address']
            ),
            'medium',
            $data['ip_address']
        );
    }

    /**
     * Helper methods for logging
     */
    public function logEvent($action, $user_id = null, $details = [], $severity = 'low') {
        if ($user_id === null) {
            $user_id = get_current_user_id();
        }
    
        $formatted_details = is_array($details) ? wp_json_encode($details) : $details;
    
        return $this->log(
            $user_id,
            $action,
            $formatted_details,
            $severity,
            $this->getClientIP()
        );
    }
    
    /**
     * Log an action (Developer API)
     *
     * @param int $user_id User ID
     * @param string $action Action name
     * @param array|string $details Action details
     * @param string $severity Severity level (low, medium, high)
     * @return bool Success status
     */
    public function log_action($user_id, $action, $details = [], $severity = 'low') {
        // Convert severity from 'info' to our internal levels
        $severity_map = [
            'info' => 'low',
            'warning' => 'medium',
            'error' => 'high'
        ];
        
        $severity = $severity_map[$severity] ?? $severity;
        
        return $this->log(
            $user_id,
            $action,
            is_array($details) ? wp_json_encode($details) : $details,
            $severity
        );
    }

    /**
     * Get client IP address
     */
    private function getClientIP() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // HTTP_X_FORWARDED_FOR can contain multiple IPs
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
        
        return filter_var($ip, FILTER_VALIDATE_IP) ?: '0.0.0.0';
    }

    /**
     * Anonymize IP address
     */
    private function anonymizeIP($ip) {
        if (empty($ip)) {
            return '';
        }
        
        // For IPv4 addresses
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // Replace last octet with zeros
            return preg_replace('/\d+$/', '0', $ip);
        }
        
        // For IPv6 addresses
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Keep first 3 parts of the IPv6 address and zero the rest
            $parts = explode(':', $ip);
            if (count($parts) >= 4) {
                return $parts[0] . ':' . $parts[1] . ':' . $parts[2] . ':0:0:0:0:0';
            }
            // Fallback: zero the last part
            return substr($ip, 0, strrpos($ip, ':')) . ':0000';
        }
        
        return '';
    }

    /**
     * Filter sensitive data from log details
     */
    private function filterSensitiveData($details) {
        if (empty($details)) {
            return '';
        }
        
        if (is_array($details)) {
            $details = wp_json_encode($details);
        }
        
        if (!is_string($details)) {
            return '';
        }
        
        // Remove potential sensitive data patterns
        $patterns = [
            // Email addresses
            '/\b[\w\.-]+@[\w\.-]+\.\w{2,4}\b/' => '[REDACTED_EMAIL]',
            
            // Credit card numbers - match common formats
            '/\b(?:\d[ -]*?){13,16}\b/' => '[REDACTED_CC]',
            
            // Passwords in various forms
            '/password[s]?\s*[:=]\s*[^\s,;]+/i' => 'password=[REDACTED]',
            '/pass[s]?\s*[:=]\s*[^\s,;]+/i' => 'pass=[REDACTED]',
            
            // Authentication tokens and keys
            '/(?:auth|api|jwt|token|secret|key)(?:_?token)?[:=]\s*[^\s,;]+/i' => '$0=[REDACTED]',
            
            // Social security numbers (US)
            '/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/' => '[REDACTED_SSN]',
            
            // Phone numbers
            '/\b(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b/' => '[REDACTED_PHONE]'
        ];
        
        // Apply all patterns
        foreach ($patterns as $pattern => $replacement) {
            $details = preg_replace($pattern, $replacement, $details);
        }
        
        return $details;
    }

    /**
     * Sanitize action name
     */
    private function sanitizeAction($action) {
        return sanitize_key($action);
    }

    /**
     * Validate severity level
     */
    private function validateSeverity($severity) {
        return in_array($severity, $this->severity_levels) ? $severity : 'low';
    }
}
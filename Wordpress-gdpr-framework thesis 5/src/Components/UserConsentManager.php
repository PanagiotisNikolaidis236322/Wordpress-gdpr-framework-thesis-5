<?php
namespace GDPRFramework\Components;

class UserConsentManager {
    private $db;
    private $settings;
    private $table_name;

    function __construct($database, $settings) {
        global $wpdb;
        
        // Ensure database is properly initialized
        $this->db = $database ?? $wpdb;
        if (!isset($this->db) || !is_object($this->db)) {
            error_log('GDPR Framework - Database initialization failed');
            throw new \Exception('Database initialization failed');
        }
        
        // Initialize table name - fixed check
        $this->table_name = $wpdb->prefix . 'gdpr_user_consents';
        
        // Ensure settings are properly initialized
        $this->settings = $settings;
        if (!isset($this->settings) || !is_object($this->settings)) {
            error_log('GDPR Framework - Settings initialization failed');
            throw new \Exception('Settings initialization failed');
        }
        
        // Initialize hooks
        $this->initializeHooks();
    }
    
    /**
     * Initialize WordPress hooks
     */
    private function initializeHooks(): void 
    {
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('wp_ajax_update_user_consent', [$this, 'handleConsentUpdate']);
        add_action('wp_ajax_nopriv_update_user_consent', [$this, 'handleConsentUpdate']);
        add_shortcode('gdpr_consent_form', [$this, 'renderConsentForm']);
    }

    public function registerSettings() {
        register_setting('gdpr_framework_settings', 'gdpr_consent_types', [
            'sanitize_callback' => [$this, 'sanitizeConsentTypes']
        ]);
    }

    public function sanitizeConsentTypes($types) {
        if (!is_array($types)) {
            return [];
        }

        $sanitized = [];
        foreach ($types as $key => $type) {
            $sanitized[sanitize_key($key)] = [
                'label' => sanitize_text_field($type['label']),
                'description' => sanitize_textarea_field($type['description']),
                'required' => !empty($type['required'])
            ];
        }

        return $sanitized;
    }

    public function getConsentStatus($type, $user_id = null) {
        if (!$user_id) {
            $user_id = get_current_user_id();
        }
    
        $query = $this->db->prepare(
            "SELECT status FROM {$this->table_name} 
             WHERE user_id = %d AND consent_type = %s 
             ORDER BY timestamp DESC LIMIT 1",
            $user_id,
            $type
        );
        
        return (bool) $this->db->get_var($query);
    }

    public function handleConsentUpdate() {
        try {
            // Verify nonce first with a more secure implementation
            if (!isset($_POST['gdpr_nonce']) || !wp_verify_nonce($_POST['gdpr_nonce'], 'gdpr_nonce')) {
                throw new \Exception(__('Security check failed.', 'wp-gdpr-framework'));
            }
    
            // Check if consents data exists and is in the expected format
            if (!isset($_POST['consents']) || !is_array($_POST['consents'])) {
                throw new \Exception(__('Invalid consent data received.', 'wp-gdpr-framework'));
            }
            
            // Get available consent types using WordPress option directly (safer)
            $available_types = get_option('gdpr_consent_types', []);
            if (empty($available_types)) {
                throw new \Exception(__('No consent types defined.', 'wp-gdpr-framework'));
            }
            
            // Determine user ID - handle both logged in and non-logged in cases
            $user_id = get_current_user_id();
            
            // For non-logged in users, either use a cookie or just exit
            if (!$user_id) {
                if (apply_filters('gdpr_allow_non_logged_in_consents', false)) {
                    // Custom implementation for non-logged in users if permitted
                    $user_id = $this->getNonLoggedInUserId();
                } else {
                    throw new \Exception(__('You must be logged in to update privacy settings.', 'wp-gdpr-framework'));
                }
            }
            
            // Process each consent type
            $updated_count = 0;
            foreach ($_POST['consents'] as $type_key => $status) {
                if (!isset($available_types[$type_key])) {
                    continue;
                }
    
                $status = (bool)$status;
                
                // Don't allow changing required consents to false
                if (!empty($available_types[$type_key]['required']) && !$status) {
                    continue;
                }
                
                // Save the consent with validated data
                if ($this->saveConsent($user_id, sanitize_key($type_key), $status)) {
                    $updated_count++;
                    do_action('gdpr_consent_updated', $user_id, $type_key, $status);
                }
            }
    
            if ($updated_count > 0) {
                wp_send_json_success([
                    'message' => __('Privacy settings updated successfully.', 'wp-gdpr-framework'),
                    'updated_count' => $updated_count
                ]);
            } else {
                throw new \Exception(__('No privacy settings were updated.', 'wp-gdpr-framework'));
            }
    
        } catch (\Exception $e) {
            error_log('GDPR Consent Update Error: ' . $e->getMessage());
            wp_send_json_error([
                'message' => $e->getMessage()
            ]);
        }
    }

    // Helper method for non-logged in users (implement only if needed)
private function getNonLoggedInUserId() {
    // This is a placeholder - implement according to your needs
    // Could use cookies, IP hashing, or other methods
    throw new \Exception(__('Non-logged in user consent not implemented.', 'wp-gdpr-framework'));
}
    
    private function saveConsent($user_id, $consent_type, $status) {
        $result = $this->db->insert(
            'gdpr_user_consents', // Use the full table name with the correct prefix
            [
                'user_id' => $user_id,
                'consent_type' => $consent_type,
                'status' => $status,
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'timestamp' => current_time('mysql')
            ],
            ['%d', '%s', '%d', '%s', '%s', '%s']
        );
    
        if ($result) {
            do_action('gdpr_consent_recorded', $user_id, $consent_type, $status);
        }
    
        return $result;
    }

    public function getConsentStats() {
        global $wpdb;
        
        $stats = [
            'total_users' => count_users()['total_users'],
            'consent_types' => []
        ];

        $consent_types = get_option('gdpr_consent_types', []);
        
        // Ensure consent_types is an array
        if (!is_array($consent_types)) {
            $consent_types = [];
        }
        
        foreach ($consent_types as $type_key => $type) {
            // Ensure $type is an array
            $type = is_array($type) ? $type : [];
            
            $count = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(DISTINCT user_id) FROM {$this->table_name}
                 WHERE consent_type = %s AND status = 1",
                $type_key
            ));

            $stats['consent_types'][$type_key] = [
                'label' => isset($type['label']) ? $type['label'] : $type_key,
                'count' => (int)$count,
                'percentage' => $stats['total_users'] > 0 
                    ? round(($count / $stats['total_users']) * 100, 1) 
                    : 0
            ];
        }

        return $stats;
    }

    function renderConsentForm($atts = [], $content = '', $shortcode = '') {
        $defaults = [
            'show_reset' => true,
            'redirect' => '',
            'login_message' => __('Please log in to manage your privacy settings.', 'wp-gdpr-framework')
        ];
        $atts = wp_parse_args($atts, $defaults);
        
        if (!is_user_logged_in()) {
            $message = $atts['login_message'];
            if ($atts['redirect']) {
                $login_url = wp_login_url($atts['redirect']);
                $message .= sprintf(' <a href="%s">%s</a>', 
                    esc_url($login_url),
                    __('Log in here', 'wp-gdpr-framework')
                );
            }
            return '<div class="gdpr-notice">' . $message . '</div>';
        }

        $this->enqueueAssets();

        $template_file = GDPR_FRAMEWORK_TEMPLATE_PATH . '/public/consent-form.php';
        
        if (!file_exists($template_file)) {
            return '<div class="gdpr-notice gdpr-error">' . 
                __('Error: Consent form template not found.', 'wp-gdpr-framework') . 
                '</div>';
        }

        $user_id = get_current_user_id();
        $consent_types = $this->settings->get('consent_types', []);
        $current_consents = $this->getCurrentUserConsents($user_id);
        $show_reset = $atts['show_reset'];

        ob_start();
        include($template_file);
        return ob_get_clean();
    }

    private function enqueueAssets() {
        wp_enqueue_style(
            'gdpr-framework-public',
            GDPR_FRAMEWORK_URL . 'assets/css/public.css',
            [],
            GDPR_FRAMEWORK_VERSION
        );

        wp_enqueue_script(
            'gdpr-framework-public',
            GDPR_FRAMEWORK_URL . 'assets/js/public.js',
            ['jquery'],
            GDPR_FRAMEWORK_VERSION,
            true
        );

        wp_localize_script('gdpr-framework-public', 'gdprConsentForm', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('gdpr_nonce'),
            'i18n' => [
                'success' => __('Your privacy preferences have been updated successfully.', 'wp-gdpr-framework'),
                'error' => __('Failed to update privacy preferences.', 'wp-gdpr-framework'),
                'updating' => __('Updating...', 'wp-gdpr-framework'),
                'update' => __('Update Privacy Settings', 'wp-gdpr-framework'),
                'confirmReset' => __('Are you sure you want to reset your privacy preferences?', 'wp-gdpr-framework')
            ]
        ]);
    }

    /**
     * Get total number of users who have given any consent
     * 
     * @return int Total number of users with consents
     */
    public function getTotalConsents(): int 
    {
        try {
            $sql = "SELECT COUNT(DISTINCT user_id) FROM {$this->table_name}";
            
            return (int) $this->db->get_var($sql);
        } catch (\Exception $e) {
            error_log('GDPR Framework - Get Total Consents Error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get number of active consents
     * 
     * @return int Number of active consents
     */
    public function getActiveConsents(): int 
    {
        try {
            $sql = "SELECT COUNT(*) FROM {$this->table_name} WHERE status = 1";
            
            return (int) $this->db->get_var($sql);
        } catch (\Exception $e) {
            error_log('GDPR Framework - Get Active Consents Error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get consent history for a user
     * 
     * @param int $user_id User ID
     * @return array Array of consent history
     */
    public function getConsentHistory(int $user_id): array 
    {
        try {
            $query = $this->db->prepare(
                "SELECT * FROM {$this->table_name} 
                 WHERE user_id = %d 
                 ORDER BY timestamp DESC",
                $user_id
            );
            
            $results = $this->db->get_results($query);
            return is_array($results) ? $results : [];
        } catch (\Exception $e) {
            error_log('GDPR Framework - Get Consent History Error: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get number of pending consent requests
     * 
     * @return int Number of pending requests
     */
    public function getPendingRequests(): int 
    {
        try {
            $query = $this->db->prepare(
                "SELECT COUNT(*) FROM {$this->table_name} 
                 WHERE status = %s",
                'pending'
            );
            
            return (int) $this->db->get_var($query);
        } catch (\Exception $e) {
            error_log('GDPR Framework - Get Pending Requests Error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Check if user has given a specific consent
     * 
     * @param string $consent_type Type of consent to check
     * @param int|null $user_id Optional user ID, defaults to current user
     * @return bool Whether user has given consent
     */
    public function hasConsent(string $consent_type, ?int $user_id = null): bool 
    {
        if (!$user_id) {
            $user_id = get_current_user_id();
        }

        if (!$user_id) {
            return false;
        }

        try {
            $query = $this->db->prepare(
                "SELECT status FROM {$this->table_name} 
                 WHERE user_id = %d 
                 AND consent_type = %s 
                 ORDER BY timestamp DESC 
                 LIMIT 1",
                $user_id,
                $consent_type
            );
            
            return (bool) $this->db->get_var($query);
        } catch (\Exception $e) {
            error_log('GDPR Framework - Check Consent Error: ' . $e->getMessage());
            return false;
        }
    }

    private function getCurrentUserConsents($user_id) {
        if (!$user_id) return [];

        $consents = [];
        $consent_types = $this->settings->get('consent_types', []);
        
        foreach ($consent_types as $type => $data) {
            $consents[$type] = $this->getConsentStatus($type, $user_id);
        }
        
        return $consents;
    }
    
    public function addDefaultConsentTypes() {
        $default_types = [
            'marketing' => [
                'label' => 'Marketing Communications',
                'description' => 'Allow us to send you marketing communications',
                'required' => false
            ],
            'analytics' => [
                'label' => 'Analytics Tracking',
                'description' => 'Allow us to analyze your usage of our website',
                'required' => false
            ],
            'necessary' => [
                'label' => 'Necessary Cookies',
                'description' => 'Required for the website to function properly',
                'required' => true
            ]
        ];

        if (!get_option('gdpr_consent_types')) {
            update_option('gdpr_consent_types', $default_types);
        }
    }
}
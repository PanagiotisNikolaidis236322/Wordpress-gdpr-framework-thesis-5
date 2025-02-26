<?php
namespace GDPRFramework\Components;

class DataPortabilityManager {
    private $db;
    private $settings;
    private $encryption;
    private $template;
    private $table_name;
    private $supported_formats = ['json', 'xml', 'csv'];

    public function __construct($database, $settings) {
        global $wpdb;
        $this->db = $database;
        $this->settings = $settings;
        $this->table_name = $wpdb->prefix . 'gdpr_data_requests';
            
        // Initialize hooks
        add_action('init', [$this, 'initLateComponents']);
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('wp_ajax_gdpr_export_data', [$this, 'handleExportRequest']);
        add_action('wp_ajax_gdpr_erase_data', [$this, 'handleErasureRequest']);
        add_action('wp_ajax_gdpr_process_request', [$this, 'handleRequestProcessing']);
        add_action('gdpr_daily_cleanup', [$this, 'cleanupExpiredExports']);
        add_shortcode('gdpr_privacy_dashboard', [$this, 'renderPrivacyDashboard']);
    }

    public function initLateComponents() {
        $gdpr = \GDPRFramework\Core\GDPRFramework::getInstance();
        if (is_null($this->encryption)) {
            $this->encryption = $gdpr->getComponent('encryption');
        }
        if (is_null($this->template)) {
            $this->template = $gdpr->getComponent('template');
        }
    }

    public function getRequestsWithUsers() {
        global $wpdb;
        return $this->db->get_results(
            "SELECT r.*, u.display_name, u.user_email 
             FROM {$this->table_name} r 
             LEFT JOIN {$wpdb->users} u ON r.user_id = u.ID 
             WHERE r.status = 'pending' 
             ORDER BY r.created_at DESC"
        );
    }

    public function getRecentExportsWithUsers($limit = 5) {
        global $wpdb;
        return $this->db->get_results($this->db->prepare(
            "SELECT r.*, u.display_name, u.user_email 
             FROM {$this->table_name} r 
             LEFT JOIN {$wpdb->users} u ON r.user_id = u.ID 
             WHERE r.request_type = 'export' 
             AND r.status = 'completed' 
             ORDER BY r.completed_at DESC 
             LIMIT %d",
            $limit
        ));
    }

    public function handleRequestProcessing() {
        check_ajax_referer('gdpr_process_request', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'wp-gdpr-framework')]);
            return;
        }

        $request_id = intval($_POST['request_id'] ?? 0);
        $request_type = sanitize_text_field($_POST['request_type'] ?? '');

        try {
            $request = $this->getRequest($request_id);
            if (!$request || $request->status !== 'pending') {
                throw new \Exception(__('Invalid request.', 'wp-gdpr-framework'));
            }

            if ($request_type === 'export') {
                $this->processExportRequest($request_id);
            } else {
                $this->processErasureRequest($request_id);
            }

            wp_send_json_success([
                'message' => __('Request processed successfully.', 'wp-gdpr-framework')
            ]);
        } catch (\Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    public function registerSettings() {
        // Register export formats setting
        register_setting(
            'gdpr_framework_settings',
            'gdpr_export_formats',
            [
                'type' => 'array',
                'default' => ['json', 'xml'],
                'sanitize_callback' => [$this, 'sanitizeExportFormats']
            ]
        );

        // Register export expiry setting
        register_setting(
            'gdpr_framework_settings',
            'gdpr_export_expiry',
            [
                'type' => 'integer',
                'default' => 48,
                'sanitize_callback' => [$this, 'sanitizeExportExpiry']
            ]
        );
    }

    public function sanitizeExportFormats($formats) {
        if (!is_array($formats)) {
            return ['json'];
        }
        return array_intersect($formats, $this->supported_formats);
    }

    // Add this new method to sanitize the export expiry value
    public function sanitizeExportExpiry($value) {
        $value = absint($value);
        
        // Ensure value is between 1 and 168 hours (1 week)
        if ($value < 1) {
            $value = 1;
        } elseif ($value > 168) {
            $value = 168;
        }
        
        return $value;
    }

    public function getExportExpiry() {
        return get_option('gdpr_export_expiry', 48);
    }

    public function cleanupExpiredExports() {
        $expiry_hours = $this->getExportExpiry();
        $expiry_time = time() - ($expiry_hours * HOUR_IN_SECONDS);
        
        $completed_exports = $this->db->get_results(
            $this->db->prepare(
                "SELECT * FROM {$this->table_name} 
                 WHERE request_type = 'export' 
                 AND status = 'completed' 
                 AND completed_at < %s",
                date('Y-m-d H:i:s', $expiry_time)
            )
        );

        foreach ($completed_exports as $export) {
            $details = json_decode($export->details, true);
            if (!empty($details['file_path']) && file_exists($details['file_path'])) {
                unlink($details['file_path']);
            }

            $this->db->update(
                'data_requests',
                ['status' => 'expired'],
                ['id' => $export->id]
            );
        }
    }

    public function handleExportRequest() {
        check_ajax_referer('gdpr_nonce', 'nonce');

        $user_id = get_current_user_id();
        if (!$user_id) {
            wp_send_json_error(__('Not authenticated', 'wp-gdpr-framework'));
            return;
        }

        try {
            $request_id = $this->createDataRequest($user_id, 'export');
            $this->processExportRequest($request_id);
            
            wp_send_json_success([
                'message' => __('Data export processed successfully.', 'wp-gdpr-framework'),
                'download_url' => $this->getExportDownloadUrl($request_id)
            ]);
        } catch (\Exception $e) {
            wp_send_json_error($e->getMessage());
        }
    }

    public function handleErasureRequest() {
        check_ajax_referer('gdpr_nonce', 'nonce');

        $user_id = get_current_user_id();
        if (!$user_id) {
            wp_send_json_error(__('Not authenticated', 'wp-gdpr-framework'));
            return;
        }

        try {
            $request_id = $this->createDataRequest($user_id, 'erasure');
            $this->processErasureRequest($request_id);
            
            wp_send_json_success([
                'message' => __('Data erasure processed successfully.', 'wp-gdpr-framework')
            ]);
        } catch (\Exception $e) {
            wp_send_json_error($e->getMessage());
        }
    }

    private function createDataRequest($user_id, $type) {
        $result = $this->db->insert(
            'data_requests',
            [
                'user_id' => $user_id,
                'request_type' => $type,
                'status' => 'pending',
                'created_at' => current_time('mysql')
            ],
            ['%d', '%s', '%s', '%s']
        );

        if (!$result) {
            throw new \Exception(__('Failed to create data request', 'wp-gdpr-framework'));
        }

        return $this->db->insert_id;
    }

    private function processExportRequest($request_id) {
        $request = $this->getRequest($request_id);
        if (!$request) {
            throw new \Exception(__('Invalid request', 'wp-gdpr-framework'));
        }

        try {
            $this->updateRequestStatus($request_id, 'processing');
            $data = $this->gatherUserData($request->user_id);
            $file_path = $this->createExportFile($data, $request_id);

            $this->db->update(
                'data_requests',
                [
                    'status' => 'completed',
                    'completed_at' => current_time('mysql'),
                    'details' => json_encode(['file_path' => $file_path])
                ],
                ['id' => $request_id],
                ['%s', '%s', '%s']
            );

            // Add audit log
            do_action('gdpr_data_exported', $request->user_id, $request_id);

        } catch (\Exception $e) {
            $this->updateRequestStatus($request_id, 'failed', $e->getMessage());
            throw $e;
        }
    }

    private function processErasureRequest($request_id) {
        $request = $this->getRequest($request_id);
        if (!$request) {
            throw new \Exception(__('Invalid request', 'wp-gdpr-framework'));
        }

        try {
            $this->updateRequestStatus($request_id, 'processing');
            $this->eraseUserData($request->user_id);
            $this->updateRequestStatus($request_id, 'completed');

            // Add audit log
        do_action('gdpr_data_erased', $request->user_id, $request_id);

        } catch (\Exception $e) {
            $this->updateRequestStatus($request_id, 'failed', $e->getMessage());
            throw $e;
        }
    }

    private function gatherUserData($user_id) {
        $user = get_userdata($user_id);
        if (!$user) {
            throw new \Exception(__('User not found', 'wp-gdpr-framework'));
        }

        $data = [
            'user_info' => [
                'ID' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'registered' => $user->user_registered
            ],
            'profile_data' => get_user_meta($user_id),
            'consents' => $this->getConsentHistory($user_id),
            'activities' => $this->getActivityLog($user_id)
        ];

        return apply_filters('gdpr_export_user_data', $data, $user_id);
    }

    private function createExportFile($data, $request_id) {
        $upload_dir = wp_upload_dir();
        $export_dir = trailingslashit($upload_dir['basedir']) . 'gdpr-exports';

        if (!file_exists($export_dir)) {
            wp_mkdir_p($export_dir);
            file_put_contents($export_dir . '/index.php', '<?php // Silence is golden');
        }

        $filename = sprintf('gdpr-export-%d-%s.json', $request_id, date('Y-m-d'));
        $file_path = $export_dir . '/' . $filename;

        $encrypted_data = $this->encryption->encrypt(json_encode($data));
        file_put_contents($file_path, $encrypted_data);

        return $file_path;
    }

    private function getExportDownloadUrl($request_id) {
        return add_query_arg([
            'action' => 'gdpr_download_export',
            'request_id' => $request_id,
            'nonce' => wp_create_nonce('gdpr_download_' . $request_id)
        ], admin_url('admin-ajax.php'));
    }

    private function eraseUserData($user_id) {
        global $wpdb;
        $wpdb->query('START TRANSACTION');

        try {
            $wpdb->delete($wpdb->prefix . 'gdpr_user_consents', ['user_id' => $user_id]);
            $wpdb->delete($wpdb->prefix . 'gdpr_user_data', ['user_id' => $user_id]);
            do_action('gdpr_erase_user_data', $user_id);
            $wpdb->query('COMMIT');
        } catch (\Exception $e) {
            $wpdb->query('ROLLBACK');
            throw $e;
        }
    }

    private function updateRequestStatus($request_id, $status, $details = '') {
        $data = ['status' => $status];
        if ($status === 'completed') {
            $data['completed_at'] = current_time('mysql');
        }
        if ($details) {
            $data['details'] = $details;
        }

        return $this->db->update(
            'data_requests',
            $data,
            ['id' => $request_id]
        );
    }

    private function getRequest($request_id) {
        $query = "SELECT * FROM {$this->table_name} WHERE id = %d";
        return $this->db->get_row([$query, $request_id]);
    }

    public function getPendingRequests() {
        $query = "SELECT * FROM {$this->table_name} 
                 WHERE status = 'pending' 
                 ORDER BY created_at DESC";
        return $this->db->get_results($query);
    }

    public function getRecentExports($user_id = null, $limit = 5) {
        if ($user_id) {
            $query = "SELECT * FROM {$this->table_name} 
                     WHERE request_type = 'export' 
                     AND user_id = %d 
                     AND status = 'completed' 
                     ORDER BY completed_at DESC 
                     LIMIT %d";
            return $this->db->get_results([$query, $user_id, $limit]);
        }
        
        $query = "SELECT * FROM {$this->table_name} 
                 WHERE request_type = 'export' 
                 AND status = 'completed' 
                 ORDER BY completed_at DESC 
                 LIMIT %d";
        return $this->db->get_results([$query, $limit]);
    }

    private function getConsentHistory($user_id) {
        $table = $this->db->get_prefix() . 'gdpr_user_consents';
        $query = "SELECT * FROM {$table} 
                 WHERE user_id = %d 
                 ORDER BY timestamp DESC";
        return $this->db->get_results([$query, $user_id]);
    }

    private function getActivityLog($user_id) {
        $table = $this->db->get_prefix() . 'gdpr_audit_log';
        $query = "SELECT * FROM {$table} 
                 WHERE user_id = %d 
                 ORDER BY timestamp DESC";
        return $this->db->get_results([$query, $user_id]);
    }

    public function renderPrivacyDashboard($atts = []) {
        if (!is_user_logged_in()) {
            return sprintf(
                '<div class="gdpr-notice gdpr-error"><p>%s</p><p><a href="%s" class="button">%s</a></p></div>',
                __('Please log in to access your privacy dashboard.', 'wp-gdpr-framework'),
                esc_url(wp_login_url(get_permalink())),
                __('Log In', 'wp-gdpr-framework')
            );
        }

        wp_enqueue_script('jquery');
        wp_enqueue_style('gdpr-framework-public');
        wp_enqueue_script('gdpr-framework-public');

        $user_id = get_current_user_id();
        
        try {
            if (!$this->template) {
                $gdpr = \GDPRFramework\Core\GDPRFramework::getInstance();
                $this->template = $gdpr->getComponent('template');
                
                if (!$this->template) {
                    throw new \Exception('Template component not initialized');
                }
            }
            
            return $this->template->render('public/privacy-dashboard', [
                'user_id' => $user_id,
                'recent_exports' => $this->getRecentExports($user_id),
                'consent_types' => get_option('gdpr_consent_types', [])
            ]);
        } catch (\Exception $e) {
            error_log('GDPR Framework Error: ' . $e->getMessage());
            return '<div class="gdpr-notice gdpr-error"><p>' . 
                   __('An error occurred while loading the privacy dashboard.', 'wp-gdpr-framework') . 
                   '</p></div>';
        }
    }
}
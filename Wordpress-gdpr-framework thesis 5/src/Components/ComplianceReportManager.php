<?php
namespace GDPRFramework\Components;

/**
 * GDPR Compliance Report Handler
 * 
 * Manages the generation and delivery of GDPR compliance reports.
 */
class ComplianceReportManager {
    private $db;
    private $settings;
    private $encryption;
    private $audit;

    public function __construct($database, $settings) {
        $this->db = $database;
        $this->settings = $settings;
        
        // Register hooks
        add_action('admin_post_gdpr_generate_report', [$this, 'handleReportGeneration']);
        add_action('gdpr_scheduled_report', [$this, 'generateScheduledReports']);
        
        // Initialize scheduled tasks
        $this->setupScheduledReports();
    }

    /**
     * Set up scheduled reports based on settings
     */
    private function setupScheduledReports() {
        $enabled = get_option('gdpr_enable_scheduled_reports', 0);
        $schedule = get_option('gdpr_report_schedule', 'monthly');
        
        // Clear existing scheduled event
        wp_clear_scheduled_hook('gdpr_scheduled_report');
        
        // If enabled, schedule new event
        if ($enabled) {
            $schedules = [
                'weekly' => 'weekly',
                'monthly' => 'monthly',
                'quarterly' => 'quarterly'
            ];
            
            if (!wp_next_scheduled('gdpr_scheduled_report')) {
                wp_schedule_event(time(), $schedules[$schedule] ?? 'monthly', 'gdpr_scheduled_report');
            }
        }
    }

    /**
     * Initialize related components
     */
    public function initializeComponents() {
        // Get GDPR Framework instance
        $gdpr = \GDPRFramework\Core\GDPRFramework::getInstance();
        
        // Initialize encryption component
        if (is_null($this->encryption)) {
            $this->encryption = $gdpr->getComponent('encryption');
        }
        
        // Initialize audit component
        if (is_null($this->audit)) {
            $this->audit = $gdpr->getComponent('audit');
        }
    }

    /**
     * Handle generating reports via admin-post.php
     */
    public function handleReportGeneration() {
        check_admin_referer('gdpr_generate_report');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to generate reports.', 'wp-gdpr-framework'));
        }
        
        $report_type = isset($_GET['report_type']) ? sanitize_key($_GET['report_type']) : '';
        $format = isset($_GET['format']) ? sanitize_key($_GET['format']) : 'csv';
        
        try {
            $report_data = $this->generateReport($report_type);
            $report_file = $this->saveReportToFile($report_data, $report_type, $format);
            
            // Record in audit log
            if (isset($this->audit)) {
                $this->audit->logEvent(
                    'report_generated',
                    get_current_user_id(),
                    [
                        'report_type' => $report_type,
                        'format' => $format
                    ],
                    'medium'
                );
            }
            
            // Serve file for download
            $this->serveReportFile($report_file, $report_type, $format);
            
        } catch (\Exception $e) {
            wp_die(sprintf(
                __('Error generating report: %s', 'wp-gdpr-framework'),
                $e->getMessage()
            ));
        }
    }

    /**
     * Generate a specific compliance report
     *
     * @param string $report_type Type of report to generate
     * @return array Report data
     */
    private function generateReport($report_type) {
        $this->initializeComponents();
        
        switch ($report_type) {
            case 'consent':
                return $this->generateConsentReport();
                
            case 'processing':
                return $this->generateProcessingReport();
                
            case 'security':
                return $this->generateSecurityReport();
                
            default:
                throw new \Exception(__('Invalid report type.', 'wp-gdpr-framework'));
        }
    }

    /**
     * Generate consent history report
     */
    private function generateConsentReport() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'gdpr_user_consents';
        $query = "SELECT c.*, u.display_name, u.user_email 
                 FROM {$table_name} c
                 LEFT JOIN {$wpdb->users} u ON c.user_id = u.ID
                 ORDER BY c.timestamp DESC";
                 
        $results = $wpdb->get_results($query);
        
        $report = [
            'title' => __('GDPR Consent History Report', 'wp-gdpr-framework'),
            'generated' => current_time('mysql'),
            'headers' => [
                __('User', 'wp-gdpr-framework'),
                __('Email', 'wp-gdpr-framework'),
                __('Consent Type', 'wp-gdpr-framework'),
                __('Status', 'wp-gdpr-framework'),
                __('IP Address', 'wp-gdpr-framework'),
                __('Timestamp', 'wp-gdpr-framework')
            ],
            'rows' => []
        ];
        
        foreach ($results as $row) {
            $report['rows'][] = [
                $row->display_name ?? __('Unknown User', 'wp-gdpr-framework'),
                $row->user_email ?? '',
                $row->consent_type,
                $row->status ? __('Granted', 'wp-gdpr-framework') : __('Withdrawn', 'wp-gdpr-framework'),
                $row->ip_address,
                $row->timestamp
            ];
        }
        
        return $report;
    }

    /**
     * Generate data processing activities report
     */
    private function generateProcessingReport() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'gdpr_data_requests';
        $query = "SELECT r.*, u.display_name, u.user_email 
                 FROM {$table_name} r
                 LEFT JOIN {$wpdb->users} u ON r.user_id = u.ID
                 ORDER BY r.created_at DESC";
                 
        $results = $wpdb->get_results($query);
        
        $report = [
            'title' => __('GDPR Data Processing Activities Report', 'wp-gdpr-framework'),
            'generated' => current_time('mysql'),
            'headers' => [
                __('User', 'wp-gdpr-framework'),
                __('Email', 'wp-gdpr-framework'),
                __('Request Type', 'wp-gdpr-framework'),
                __('Status', 'wp-gdpr-framework'),
                __('Created', 'wp-gdpr-framework'),
                __('Completed', 'wp-gdpr-framework')
            ],
            'rows' => []
        ];
        
        foreach ($results as $row) {
            $report['rows'][] = [
                $row->display_name ?? __('Unknown User', 'wp-gdpr-framework'),
                $row->user_email ?? '',
                ucfirst($row->request_type),
                ucfirst($row->status),
                $row->created_at,
                $row->completed_at ?? '-'
            ];
        }
        
        return $report;
    }

    /**
     * Generate security and encryption report
     */
    private function generateSecurityReport() {
        // Get encryption status
        $encryption_enabled = get_option('gdpr_enable_encryption', 1);
        $key_exists = get_option('gdpr_encryption_key') ? true : false;
        $last_rotation = get_option('gdpr_last_key_rotation');
        
        // Get login security settings
        $max_attempts = get_option('gdpr_max_login_attempts', 5);
        $lockout_duration = get_option('gdpr_lockout_duration', 900);
        
        // Get audit log settings
        $tamper_protection = get_option('gdpr_enable_tamper_protection', 1);
        $audit_retention = get_option('gdpr_audit_retention_days', 365);
        
        // Get recent security events
        $security_events = [];
        if (isset($this->audit)) {
            $events = $this->audit->getAuditLog([
                'severity' => 'high',
                'limit' => 100
            ]);
            $security_events = $events['logs'] ?? [];
        }
        
        $report = [
            'title' => __('GDPR Security Compliance Report', 'wp-gdpr-framework'),
            'generated' => current_time('mysql'),
            'sections' => [
                'encryption' => [
                    'title' => __('Encryption Settings', 'wp-gdpr-framework'),
                    'items' => [
                        __('Encryption Enabled', 'wp-gdpr-framework') => $encryption_enabled ? __('Yes', 'wp-gdpr-framework') : __('No', 'wp-gdpr-framework'),
                        __('Encryption Key Status', 'wp-gdpr-framework') => $key_exists ? __('Configured', 'wp-gdpr-framework') : __('Not Configured', 'wp-gdpr-framework'),
                        __('Encryption Algorithm', 'wp-gdpr-framework') => get_option('gdpr_encryption_algorithm', 'aes-256-cbc'),
                        __('Last Key Rotation', 'wp-gdpr-framework') => $last_rotation ? date_i18n(get_option('date_format'), $last_rotation) : __('Never', 'wp-gdpr-framework'),
                        __('Automatic Key Rotation', 'wp-gdpr-framework') => get_option('gdpr_auto_key_rotation', 0) ? __('Enabled', 'wp-gdpr-framework') : __('Disabled', 'wp-gdpr-framework')
                    ]
                ],
                'access_control' => [
                    'title' => __('Access Control Settings', 'wp-gdpr-framework'),
                    'items' => [
                        __('Maximum Login Attempts', 'wp-gdpr-framework') => $max_attempts,
                        __('Lockout Duration', 'wp-gdpr-framework') => sprintf(__('%d seconds', 'wp-gdpr-framework'), $lockout_duration)
                    ]
                ],
                'audit_logging' => [
                    'title' => __('Audit Logging Settings', 'wp-gdpr-framework'),
                    'items' => [
                        __('Tamper-Proof Logging', 'wp-gdpr-framework') => $tamper_protection ? __('Enabled', 'wp-gdpr-framework') : __('Disabled', 'wp-gdpr-framework'),
                        __('Audit Log Retention', 'wp-gdpr-framework') => sprintf(__('%d days', 'wp-gdpr-framework'), $audit_retention)
                    ]
                ]
            ],
            'events' => [
                'title' => __('Recent Security Events', 'wp-gdpr-framework'),
                'headers' => [
                    __('Date', 'wp-gdpr-framework'),
                    __('User', 'wp-gdpr-framework'),
                    __('Action', 'wp-gdpr-framework'),
                    __('Details', 'wp-gdpr-framework')
                ],
                'rows' => []
            ]
        ];
        
        // Add security events
        foreach ($security_events as $event) {
            $user = get_userdata($event->user_id);
            $report['events']['rows'][] = [
                date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($event->timestamp)),
                $user ? $user->display_name : __('System', 'wp-gdpr-framework'),
                $event->action,
                $event->details
            ];
        }
        
        return $report;
    }

    /**
     * Save report data to a file
     *
     * @param array $report_data Report data structure
     * @param string $report_type Type of report
     * @param string $format File format (csv, json, html)
     * @return string File path
     */
    private function saveReportToFile($report_data, $report_type, $format = 'csv') {
        $upload_dir = wp_upload_dir();
        $reports_dir = trailingslashit($upload_dir['basedir']) . 'gdpr-reports';
        
        // Create directory if it doesn't exist
        if (!file_exists($reports_dir)) {
            wp_mkdir_p($reports_dir);
            file_put_contents($reports_dir . '/index.php', '<?php // Silence is golden');
            
            // Create .htaccess to prevent direct access
            file_put_contents($reports_dir . '/.htaccess', 'deny from all');
        }
        
        // Generate filename
        $filename = sprintf(
            'gdpr-%s-report-%s.%s',
            $report_type,
            date('Y-m-d-His'),
            $format
        );
        
        $file_path = $reports_dir . '/' . $filename;
        
        // Format and save the report
        switch ($format) {
            case 'json':
                file_put_contents($file_path, wp_json_encode($report_data, JSON_PRETTY_PRINT));
                break;
                
            case 'html':
                file_put_contents($file_path, $this->formatReportAsHtml($report_data));
                break;
                
            case 'csv':
            default:
                $this->saveReportAsCsv($file_path, $report_data);
                break;
        }
        
        return $file_path;
    }

    /**
     * Save report data as CSV file
     */
    private function saveReportAsCsv($file_path, $report_data) {
        $fp = fopen($file_path, 'w');
        
        // Add UTF-8 BOM for proper Excel handling
        fputs($fp, chr(0xEF) . chr(0xBB) . chr(0xBF));
        
        // Add report title and generation date
        fputcsv($fp, [$report_data['title']]);
        fputcsv($fp, [sprintf(__('Generated: %s', 'wp-gdpr-framework'), $report_data['generated'])]);
        fputcsv($fp, []); // Empty row
        
        // If we have sections (for security report)
        if (isset($report_data['sections'])) {
            foreach ($report_data['sections'] as $section) {
                fputcsv($fp, [$section['title']]);
                
                foreach ($section['items'] as $name => $value) {
                    fputcsv($fp, [$name, $value]);
                }
                
                fputcsv($fp, []); // Empty row
            }
            
            // Add events section
            if (isset($report_data['events'])) {
                fputcsv($fp, [$report_data['events']['title']]);
                fputcsv($fp, $report_data['events']['headers']);
                
                foreach ($report_data['events']['rows'] as $row) {
                    fputcsv($fp, $row);
                }
            }
        } 
        // Regular tabular data
        else if (isset($report_data['headers']) && isset($report_data['rows'])) {
            fputcsv($fp, $report_data['headers']);
            
            foreach ($report_data['rows'] as $row) {
                fputcsv($fp, $row);
            }
        }
        
        fclose($fp);
    }

    /**
     * Format report data as HTML
     */
    private function formatReportAsHtml($report_data) {
        ob_start();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title><?php echo esc_html($report_data['title']); ?></title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
                h1 { color: #0073aa; }
                h2 { color: #0073aa; margin-top: 30px; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .meta { color: #666; font-style: italic; margin-bottom: 30px; }
            </style>
        </head>
        <body>
            <h1><?php echo esc_html($report_data['title']); ?></h1>
            <div class="meta">
                <?php echo sprintf(esc_html__('Generated: %s', 'wp-gdpr-framework'), $report_data['generated']); ?>
            </div>
            
            <?php 
            // If we have sections (for security report)
            if (isset($report_data['sections'])):
                foreach ($report_data['sections'] as $section): 
            ?>
                <h2><?php echo esc_html($section['title']); ?></h2>
                <table>
                    <tbody>
                        <?php foreach ($section['items'] as $name => $value): ?>
                            <tr>
                                <th><?php echo esc_html($name); ?></th>
                                <td><?php echo esc_html($value); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php 
                endforeach;
                
                // Add events section
                if (isset($report_data['events'])): 
            ?>
                <h2><?php echo esc_html($report_data['events']['title']); ?></h2>
                <table>
                    <thead>
                        <tr>
                            <?php foreach ($report_data['events']['headers'] as $header): ?>
                                <th><?php echo esc_html($header); ?></th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($report_data['events']['rows'] as $row): ?>
                            <tr>
                                <?php foreach ($row as $cell): ?>
                                    <td><?php echo esc_html($cell); ?></td>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php 
                endif;
                
            // Regular tabular data
            elseif (isset($report_data['headers']) && isset($report_data['rows'])): 
            ?>
                <table>
                    <thead>
                        <tr>
                            <?php foreach ($report_data['headers'] as $header): ?>
                                <th><?php echo esc_html($header); ?></th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($report_data['rows'] as $row): ?>
                            <tr>
                                <?php foreach ($row as $cell): ?>
                                    <td><?php echo esc_html($cell); ?></td>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    /**
     * Serve the report file to the user
     */
    private function serveReportFile($file_path, $report_type, $format) {
        if (!file_exists($file_path)) {
            wp_die(__('Report file not found.', 'wp-gdpr-framework'));
        }
        
        // Set appropriate headers
        switch ($format) {
            case 'json':
                header('Content-Type: application/json; charset=utf-8');
                break;
                
            case 'html':
                header('Content-Type: text/html; charset=utf-8');
                break;
                
            case 'csv':
            default:
                header('Content-Type: text/csv; charset=utf-8');
                break;
        }
        
        // Set download headers
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        header('Content-Length: ' . filesize($file_path));
        header('Cache-Control: no-cache, must-revalidate');
        
        // Output file contents
        readfile($file_path);
        exit;
    }

    /**
     * Generate and send scheduled reports
     */
    public function generateScheduledReports() {
        $this->initializeComponents();
        
        // Check if scheduled reports are enabled
        if (!get_option('gdpr_enable_scheduled_reports', 0)) {
            return;
        }
        
        // Get email recipients
        $email_recipients = get_option('gdpr_report_email', get_option('admin_email'));
        if (empty($email_recipients)) {
            return;
        }
        
        // Generate all report types
        $report_types = ['consent', 'processing', 'security'];
        $attachments = [];
        
        foreach ($report_types as $report_type) {
            try {
                $report_data = $this->generateReport($report_type);
                $file_path = $this->saveReportToFile($report_data, $report_type, 'csv');
                $attachments[] = $file_path;
            } catch (\Exception $e) {
                error_log('GDPR Framework - Error generating scheduled report: ' . $e->getMessage());
            }
        }
        
        // Send email with attachments
        if (!empty($attachments)) {
            $site_name = get_bloginfo('name');
            $subject = sprintf(__('[%s] GDPR Compliance Reports', 'wp-gdpr-framework'), $site_name);
            
            $message = sprintf(
                __('Hello,

Attached are the latest GDPR compliance reports for %s.

These reports include:
- Consent History Report
- Data Processing Activities Report
- Security Compliance Report

Please keep these reports secure as they may contain sensitive information.

This is an automated message from the WordPress GDPR Compliance Framework.', 'wp-gdpr-framework'),
                $site_name
            );
            
            $headers = [
                'Content-Type: text/plain; charset=UTF-8',
                'From: WordPress GDPR Framework <' . get_option('admin_email') . '>'
            ];
            
            wp_mail($email_recipients, $subject, $message, $headers, $attachments);
            
            // Log report generation in audit log
            if (isset($this->audit)) {
                $this->audit->logEvent(
                    'scheduled_reports_sent',
                    0,
                    [
                        'recipients' => $email_recipients,
                        'reports' => implode(', ', $report_types)
                    ],
                    'medium'
                );
            }
        }
    }
}
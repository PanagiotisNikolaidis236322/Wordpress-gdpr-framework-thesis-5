<?php
namespace GDPRFramework\Core;

class Settings {
    private $options = [];
    private $option_prefix = 'gdpr_';

    public function __construct() {
        $this->loadSettings();
        add_action('admin_init', [$this, 'registerSettings']);
    }

    private function loadSettings() {
        $default_settings = $this->getDefaultSettings();
        
        foreach ($default_settings as $key => $default) {
            $this->options[$key] = get_option(
                $this->option_prefix . $key, 
                $default
            );
        }
    }

    private function getDefaultSettings() {
        return [
            'enforcement_mode' => 'basic', // Default to Basic mode
            'consent_types' => [
                'marketing' => [
                    'label' => __('Marketing Communications', 'wp-gdpr-framework'),
                    'description' => __('Allow us to send marketing communications', 'wp-gdpr-framework'),
                    'required' => false
                ],
                'analytics' => [
                    'label' => __('Analytics Tracking', 'wp-gdpr-framework'),
                    'description' => __('Allow analytics tracking for website improvement', 'wp-gdpr-framework'),
                    'required' => false
                ],
                'necessary' => [
                    'label' => __('Necessary Cookies', 'wp-gdpr-framework'),
                    'description' => __('Required for the website to function properly', 'wp-gdpr-framework'),
                    'required' => true
                ]
            ],
            'enable_cookie_banner' => 1,
            'cookie_expiry' => 30,
            'enable_consent_logging' => 1,
            'enable_version_control' => 1,
            'enable_self_service' => 1,
            'auto_approve_verified' => 0,
            'retention_periods' => [
                'audit_logs' => 365,
                'user_data' => 730,
                'consent_records' => 1825
            ],
            'privacy_policy_page' => 0,
            'dpo_email' => '',
            'enable_encryption' => 1,
            'encryption_algorithm' => 'aes-256-cbc',
            'auto_key_rotation' => 0,
            'export_formats' => ['json', 'xml', 'csv'],
            'enable_tamper_protection' => 1,
            'audit_retention_days' => 365,
            'enable_scheduled_reports' => 0,
            'report_schedule' => 'monthly',
            'report_email' => '',
            'cookie_settings' => [
                'consent_expiry' => 365,
                'cookie_expiry' => 30
            ]
        ];
    }

    public function registerSettings() {
        // General Settings
        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'privacy_policy_page',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'dpo_email',
            ['sanitize_callback' => 'sanitize_email']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'retention_days',
            ['sanitize_callback' => 'absint']
        );

        // Enforcement Mode Settings
        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enforcement_mode',
            ['sanitize_callback' => [$this, 'sanitizeEnforcementMode']]
        );

        // Consent Management Settings
        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'consent_types',
            ['sanitize_callback' => [$this, 'sanitizeConsentTypes']]
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enable_cookie_banner',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'cookie_expiry',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enable_consent_logging',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enable_version_control',
            ['sanitize_callback' => 'absint']
        );

        // User Rights Settings
        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enable_self_service',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'auto_approve_verified',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'export_formats',
            ['sanitize_callback' => [$this, 'sanitizeExportFormats']]
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'export_expiry',
            ['sanitize_callback' => [$this, 'sanitizeExportExpiry']]
        );

        // Security Settings
        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enable_encryption',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'auto_key_rotation',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'max_login_attempts',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'lockout_duration',
            ['sanitize_callback' => 'absint']
        );

        // Audit & Reports Settings
        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enable_tamper_protection',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'audit_retention_days',
            ['sanitize_callback' => [$this, 'sanitizeRetentionDays']]
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'enable_scheduled_reports',
            ['sanitize_callback' => 'absint']
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'report_schedule',
            ['sanitize_callback' => [$this, 'sanitizeReportSchedule']]
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'report_email',
            ['sanitize_callback' => [$this, 'sanitizeEmailList']]
        );

        register_setting(
            'gdpr_framework_settings',
            $this->option_prefix . 'retention_periods',
            ['sanitize_callback' => [$this, 'sanitizeRetentionPeriods']]
        );
    }

    public function sanitizeConsentTypes($consent_types) {
        if (!is_array($consent_types)) {
            return [];
        }
    
        $sanitized = [];
        foreach ($consent_types as $key => $type) {
            // Ensure $type is an array
            $type = is_array($type) ? $type : [];
            
            $sanitized[sanitize_key($key)] = [
                'label' => isset($type['label']) ? sanitize_text_field($type['label']) : '',
                'description' => isset($type['description']) ? sanitize_textarea_field($type['description']) : '',
                'required' => !empty($type['required'])
            ];
        }
    
        return $sanitized;
    }

    public function sanitizeRetentionPeriods($periods) {
        if (!is_array($periods)) {
            return $this->getDefaultSettings()['retention_periods'];
        }

        $sanitized = [];
        foreach ($periods as $key => $days) {
            $sanitized[sanitize_key($key)] = absint($days);
        }
        return $sanitized;
    }

    public function sanitizeEnforcementMode($mode) {
        return in_array($mode, ['basic', 'advanced']) ? $mode : 'basic';
    }

    public function sanitizeExportFormats($formats) {
        if (!is_array($formats)) {
            return ['json'];
        }
        return array_intersect($formats, ['json', 'xml', 'csv']);
    }

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

    public function sanitizeRetentionDays($days) {
        $days = absint($days);
        return $days < 30 ? 30 : $days;
    }

    public function sanitizeReportSchedule($schedule) {
        $valid_schedules = ['weekly', 'monthly', 'quarterly'];
        return in_array($schedule, $valid_schedules) ? $schedule : 'monthly';
    }

    public function sanitizeEmailList($emails) {
        $emails_array = explode(',', $emails);
        $sanitized = [];
        
        foreach ($emails_array as $email) {
            $email = trim($email);
            if (is_email($email)) {
                $sanitized[] = $email;
            }
        }
        
        return implode(', ', $sanitized);
    }

    public function setDefaults() {
        $defaults = $this->getDefaultSettings();
        foreach ($defaults as $key => $value) {
            if (!get_option($this->option_prefix . $key)) {
                update_option($this->option_prefix . $key, $value);
            }
        }
    }

    public function get($key, $default = null) {
        return $this->options[$key] ?? $default;
    }

    public function set($key, $value) {
        $this->options[$key] = $value;
        return update_option($this->option_prefix . $key, $value);
    }

    public function delete($key) {
        unset($this->options[$key]);
        return delete_option($this->option_prefix . $key);
    }
}
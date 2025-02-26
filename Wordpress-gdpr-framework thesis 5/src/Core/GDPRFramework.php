<?php
namespace GDPRFramework\Core;

/**
 * Main GDPR Framework Class
 * 
 * Handles the initialization and coordination of all GDPR functionality
 */
class GDPRFramework {
    /** @var GDPRFramework|null */
    private static $instance = null;

    /** @var array */
    public $components = [];

    /** @var Database */
    public $database;

    /** @var Settings */
    public $settings;

    /** @var string */
    private $version;

    /**
     * Get singleton instance
     *
     * @return GDPRFramework
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Private constructor to enforce singleton pattern
     */
    private function __construct() {
        $this->version = GDPR_FRAMEWORK_VERSION;
        try {
            $this->setupCore();
            $this->initializeComponents();
            $this->initializeHooks();
            $this->setupCleanupSchedule();
        } catch (\Exception $e) {
            error_log('GDPR Framework Error: ' . $e->getMessage());
            add_action('admin_notices', [$this, 'displayInitializationError']);
        }
    }

    /**
     * Setup core components
     */
    private function setupCore() {
        $this->database = new Database();
        $this->settings = new Settings();
    }

    /**
     * Initialize essential components
     */
    private function initializeComponents() {
        try {
            // First, check if database tables exist - if not, attempt to create them
            if (!$this->database->verifyTables()) {
                $this->database->createTables();
                // If still not successful, log error but continue initialization
                if (!$this->database->verifyTables()) {
                    error_log('GDPR Framework - Failed to create database tables');
                }
            }
            
            // Initialize essential components first with proper error handling
            try {
                $this->components['template'] = new \GDPRFramework\Components\TemplateRenderer(
                    $this->settings
                );
            } catch (\Exception $e) {
                error_log('GDPR Framework - Template component initialization failed: ' . $e->getMessage());
                // Create a fallback simple template renderer
                $this->components['template'] = new class($this->settings) {
                    public function __construct($settings) {
                        $this->settings = $settings;
                    }
                    public function render($template, $data = []) {
                        return '<div class="notice notice-error"><p>' . 
                               sprintf(__('Template %s could not be rendered due to an error.', 'wp-gdpr-framework'), esc_html($template)) . 
                               '</p></div>';
                    }
                };
            }
    
            // Initialize LoggingAuditManager with error handling
            try {
                $this->components['audit'] = new \GDPRFramework\Components\LoggingAuditManager(
                    $this->database,
                    $this->settings
                );
            } catch (\Exception $e) {
                error_log('GDPR Framework - Audit component initialization failed: ' . $e->getMessage());
                // Create a fallback audit logger that just logs to error_log
                $this->components['audit'] = new class($this->database, $this->settings) {
                    public function __construct($database, $settings) {
                        $this->database = $database;
                        $this->settings = $settings;
                    }
                    public function log($user_id, $action, $details = '', $severity = 'low', $ip_address = '') {
                        error_log("GDPR Framework - Audit Log: User ID: $user_id, Action: $action, Details: $details, Severity: $severity");
                        return true;
                    }
                    // Implement minimal required methods
                    public function logEvent($action, $user_id = null, $details = [], $severity = 'low') {
                        $details_str = is_array($details) ? json_encode($details) : $details;
                        error_log("GDPR Framework - Audit Event: Action: $action, User ID: $user_id, Details: $details_str, Severity: $severity");
                        return true;
                    }
                };
            }
            
            // Initialize remaining components immediately rather than waiting for init
            $this->initializeRemainingComponents();
            
            // Add action to ensure components are initialized
            add_action('init', [$this, 'ensureComponentsInitialized'], 10);
            
        } catch (\Exception $e) {
            error_log('GDPR Framework Component Init Error: ' . $e->getMessage());
            throw $e; // Re-throw to be caught by the constructor
        }
    }
    
    /**
     * Initialize remaining components immediately
     */
    private function initializeRemainingComponents() {
        try {
            // Basic components as before
            $basic_components = [
                'encryption' => '\GDPRFramework\Components\DataEncryptionManager',
                'consent' => '\GDPRFramework\Components\UserConsentManager',
                'access' => '\GDPRFramework\Components\AccessControlManager',
                'portability' => '\GDPRFramework\Components\DataPortabilityManager',
                'reports' => '\GDPRFramework\Components\ComplianceReportManager'
            ];
            
            // New advanced components  
            $advanced_components = [
                'caching' => '\GDPRFramework\Components\CachingManager',
                'requirements' => '\GDPRFramework\Components\SystemRequirementsChecker',
                'api_security' => '\GDPRFramework\Components\APISecurity',
                'network' => '\GDPRFramework\Components\NetworkConfiguration',
                'mfa' => '\GDPRFramework\Components\MultiFactorAuthManager',
                'rbac' => '\GDPRFramework\Components\RBACManager',
                'security' => '\GDPRFramework\Components\SecurityEnforcer'
            ];
            
            // Combine all components
            $component_classes = array_merge($basic_components, $advanced_components);
            
            foreach ($component_classes as $key => $class) {
                if (!isset($this->components[$key])) {
                    try {
                        // Different components need different parameters
                        // First check if the class exists before attempting to instantiate
                        if (!class_exists($class)) {
                            error_log("GDPR Framework - Class not found: $class");
                            continue;
                        }
                        
                        if ($key === 'caching' || $key === 'network' || $key === 'requirements') {
                            // These components only need settings
                            $this->components[$key] = new $class(
                                $this->settings
                            );
                        } else {
                            // Most components need both database and settings
                            $this->components[$key] = new $class(
                                $this->database,
                                $this->settings
                            );
                        }
                    } catch (\Exception $e) {
                        error_log("GDPR Framework - Failed to initialize $key component: " . $e->getMessage());
                        // Continue with other components
                    }
                }
            }
    
            // Register cleanup task
            if (isset($this->components['audit'])) {
                add_action('gdpr_daily_cleanup', [$this->components['audit'], 'cleanupOldLogs']);
            }
            
            // Register database optimization task
            add_action('gdpr_weekly_maintenance', [$this->database, 'optimizeTables']);
            
        } catch (\Exception $e) {
            error_log('GDPR Framework Component Init Error: ' . $e->getMessage());
            // Don't throw, just log and continue with what we have
        }
    }

    /**
     * Ensure components are initialized (called during WordPress init)
     */
    public function ensureComponentsInitialized() {
        $this->initializeRemainingComponents();
    }

    /**
     * Initialize WordPress hooks
     */
    private function initializeHooks() {
        // Admin
        add_action('admin_menu', [$this, 'addAdminMenu']);
        add_action('admin_init', [$this, 'initializeAdmin']);
        add_filter('plugin_action_links_' . plugin_basename(GDPR_FRAMEWORK_PATH . 'wp-gdpr-framework.php'), 
            [$this, 'addPluginLinks']
        );

        // Assets
        add_action('admin_enqueue_scripts', [$this, 'enqueueAdminAssets']);
        add_action('wp_enqueue_scripts', [$this, 'enqueuePublicAssets']);

        // AJAX handlers
        $this->initializeAjaxHandlers();

        // Add admin-post.php handlers
        add_action('admin_post_gdpr_generate_report', [$this, 'handleAdminPostActions']);

        // Cron jobs
        add_action('init', [$this, 'setupCronJobs']);
    }

    /**
     * Initialize AJAX handlers
     */
    private function initializeAjaxHandlers() {
        $ajax_actions = [
            'gdpr_update_consent',
            'gdpr_export_data',
            'gdpr_erase_data',
            'gdpr_get_audit_log',
            'gdpr_process_request',
            'gdpr_generate_report'
        ];

        foreach ($ajax_actions as $action) {
            add_action('wp_ajax_' . $action, [$this, 'handleAjax']);
            add_action('wp_ajax_nopriv_' . $action, [$this, 'handleAjaxNoPriv']);
        }

        // Add specific handler for consent updates
        add_action('wp_ajax_update_user_consent', [$this, 'handleConsentUpdate']);
        add_action('wp_ajax_nopriv_update_user_consent', [$this, 'handleConsentUpdate']);

        // Add specific handler for process request
        add_action('wp_ajax_gdpr_process_request', function() {
            if (isset($this->components['portability'])) {
                $this->components['portability']->handleRequestProcessing();
            }
        });
        
        // Add specific handler for generating reports
        add_action('wp_ajax_gdpr_generate_report', function() {
            if (isset($this->components['reports'])) {
                $this->components['reports']->handleReportGeneration();
            }
        });
    }

    /**
     * Handle authenticated AJAX requests
     */
    public function handleAjax() {
        $action = $_REQUEST['action'] ?? '';
        
        switch ($action) {
            case 'gdpr_update_consent':
                if (isset($this->components['consent'])) {
                    $this->components['consent']->handleConsentUpdate();
                }
                break;
                
            case 'gdpr_export_data':
                if (isset($this->components['portability'])) {
                    $this->components['portability']->handleExportRequest();
                }
                break;
                
            case 'gdpr_erase_data':
                if (isset($this->components['portability'])) {
                    $this->components['portability']->handleErasureRequest();
                }
                break;
                
            case 'gdpr_get_audit_log':
                if (isset($this->components['audit'])) {
                    $this->components['audit']->handleLogRequest();
                }
                break;
                
            case 'gdpr_generate_report':
                if (isset($this->components['reports'])) {
                    $this->components['reports']->handleReportGeneration();
                }
                break;
        }
        
        wp_die();
    }

    public function handleConsentUpdate() {
        if (isset($this->components['consent'])) {
            $this->components['consent']->handleConsentUpdate();
        } else {
            wp_send_json_error([
                'message' => __('Consent management not initialized.', 'wp-gdpr-framework')
            ]);
        }
    }

    /**
     * Handle non-authenticated AJAX requests
     */
    public function handleAjaxNoPriv() {
        wp_send_json_error('Authentication required');
    }

    /**
     * Add admin menu items
     */
    public function addAdminMenu() {
        add_menu_page(
            __('GDPR Framework', 'wp-gdpr-framework'),
            __('GDPR Framework', 'wp-gdpr-framework'),
            'manage_options',
            'gdpr-framework',
            [$this, 'renderDashboard'],
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'gdpr-framework',
            __('Dashboard', 'wp-gdpr-framework'),
            __('Dashboard', 'wp-gdpr-framework'),
            'manage_options',
            'gdpr-framework',
            [$this, 'renderDashboard']
        );

        add_submenu_page(
            'gdpr-framework',
            __('Settings', 'wp-gdpr-framework'),
            __('Settings', 'wp-gdpr-framework'),
            'manage_options',
            'gdpr-framework-settings',
            [$this, 'renderSettings']
        );

        add_submenu_page(
            'gdpr-framework',
            __('Audit Log', 'wp-gdpr-framework'),
            __('Audit Log', 'wp-gdpr-framework'),
            'manage_options',
            'gdpr-framework-audit',
            [$this, 'renderAuditLog']
        );
        
        // Add new System page to display technical requirements
        add_submenu_page(
            'gdpr-framework',
            __('System Status', 'wp-gdpr-framework'),
            __('System Status', 'wp-gdpr-framework'),
            'manage_options',
            'gdpr-framework-system',
            [$this, 'renderSystemStatus']
        );
    }

    /**
     * Initialize admin settings
     */
    public function initializeAdmin() {
        register_setting('gdpr_framework_settings', 'gdpr_retention_days');
        register_setting('gdpr_framework_settings', 'gdpr_consent_types');
        
        $this->addCleanupSettings();
    }

    /**
     * Add plugin action links
     */
    public function addPluginLinks($links) {
        $plugin_links = [
            '<a href="' . admin_url('admin.php?page=gdpr-framework-settings') . '">' . 
                __('Settings', 'wp-gdpr-framework') . '</a>',
            '<a href="https://example.com/docs/gdpr-framework">' . 
                __('Documentation', 'wp-gdpr-framework') . '</a>'
        ];
        return array_merge($plugin_links, $links);
    }

    /**
     * Enqueue admin assets
     * 
     * @param string $hook Current admin page hook
     * @return void
     */
    public function enqueueAdminAssets($hook) {
        // Only load on plugin pages
        if (strpos($hook, 'gdpr-framework') === false && strpos($hook, 'gdpr_framework') === false) {
            return;
        }
        
        // Properly enqueue jQuery and its dependencies
        wp_enqueue_script('jquery');
        
        // Enqueue admin styles
        wp_enqueue_style(
            'gdpr-framework-admin',
            GDPR_FRAMEWORK_URL . 'assets/css/admin.css',
            array(),
            $this->version
        );

        // Enqueue admin scripts with correct dependencies
        wp_enqueue_script(
            'gdpr-framework-admin',
            GDPR_FRAMEWORK_URL . 'assets/js/admin.js',
            array('jquery'),
            $this->version,
            true    // Load in footer
        );

        // Localize script with necessary data and translations
        wp_localize_script(
            'gdpr-framework-admin', 
            'gdprFrameworkAdmin', 
            array(
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('gdpr_admin_nonce'),
                'i18n' => array(
                    'confirmDelete' => __('Are you sure you want to delete this item?', 'wp-gdpr-framework'),
                    'confirmExport' => __('Are you sure you want to process this export request?', 'wp-gdpr-framework'),
                    'confirmErasure' => __('Are you sure you want to erase this data? This action cannot be undone.', 'wp-gdpr-framework'),
                    'confirmRotation' => __('Are you sure you want to rotate the encryption key? This process cannot be interrupted.', 'wp-gdpr-framework'),
                    'processing' => __('Processing...', 'wp-gdpr-framework'),
                    'processRequest' => __('Process Request', 'wp-gdpr-framework'),
                    'rotating' => __('Rotating Key...', 'wp-gdpr-framework'),
                    'rotateKey' => __('Rotate Encryption Key', 'wp-gdpr-framework'),
                    'rotateSuccess' => __('Encryption key rotated successfully.', 'wp-gdpr-framework'),
                    'cleaning' => __('Cleaning...', 'wp-gdpr-framework'),
                    'cleanup' => __('Run Cleanup', 'wp-gdpr-framework'),
                    'generating' => __('Generating...', 'wp-gdpr-framework'),
                    'generate' => __('Generate', 'wp-gdpr-framework'),
                    'error' => __('An error occurred. Please try again.', 'wp-gdpr-framework'),
                    'saved' => __('Settings saved successfully.', 'wp-gdpr-framework')
                )
            )
        );
    }

    /**
     * Enqueue public assets
     */
    public function enqueuePublicAssets() {
        if (!$this->shouldLoadPublicAssets()) {
            return;
        }

        wp_enqueue_style(
            'gdpr-framework-public',
            GDPR_FRAMEWORK_URL . 'assets/css/public.css',
            [],
            $this->version
        );

        wp_enqueue_script(
            'gdpr-framework-public',
            GDPR_FRAMEWORK_URL . 'assets/js/public.js',
            ['jquery'],
            $this->version,
            true
        );

        wp_localize_script('gdpr-framework-public', 'gdprFramework', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('gdpr_nonce')
        ]);
    }

    /**
     * Check if public assets should be loaded
     */
    private function shouldLoadPublicAssets() {
        global $post;
        
        // Check if get_post() returns a valid post object
        if (!$post instanceof \WP_Post) {
            return false;
        }
            
        return is_user_logged_in() || 
               has_shortcode($post->post_content ?? '', 'gdpr_consent_form') ||
               has_shortcode($post->post_content ?? '', 'gdpr_privacy_dashboard');
    }

    /**
     * Render dashboard page
     */
    public function renderDashboard() {
        try {
            if (!isset($this->components['template'])) {
                throw new \Exception(__('Template component not initialized.', 'wp-gdpr-framework'));
            }
            
            // Get system requirements info if available
            $requirements_info = [];
            $requirements_summary = [];
            
            if (isset($this->components['requirements'])) {
                $requirements_info = $this->components['requirements']->checkAll();
                $requirements_summary = $this->components['requirements']->getSummary();
            }
    
            echo $this->components['template']->render('admin/dashboard', [
                'consent' => $this->components['consent'] ?? null,
                'portability' => $this->components['portability'] ?? null,
                'encryption' => $this->components['encryption'] ?? null,
                'audit' => $this->components['audit'] ?? null,
                'caching' => $this->components['caching'] ?? null,
                'network' => $this->components['network'] ?? null,
                'stats' => $this->getStats(),
                'database_ok' => $this->database->verifyTables(),
                'cleanup_status' => [
                    'next_run' => wp_next_scheduled('gdpr_daily_cleanup') 
                        ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), wp_next_scheduled('gdpr_daily_cleanup'))
                        : __('Not scheduled', 'wp-gdpr-framework')
                ],
                'requirements_info' => $requirements_info,
                'requirements_summary' => $requirements_summary,
                'database_stats' => $this->database->getTableStatus()
            ]);
        } catch (\Exception $e) {
            echo '<div class="notice notice-error"><p>' . 
                 esc_html__('Error loading dashboard: ', 'wp-gdpr-framework') . 
                 esc_html($e->getMessage()) . '</p></div>';
        }
    }

    /**
     * Render settings page
     */
    public function renderSettings() {
        if (!isset($this->components['template'])) {
            echo '<div class="wrap"><h1>' . esc_html__('GDPR Framework Settings', 'wp-gdpr-framework') . '</h1>';
            echo '<p>' . esc_html__('Settings component not initialized.', 'wp-gdpr-framework') . '</p></div>';
            return;
        }
    
        echo $this->components['template']->render('admin/settings', [
            'settings' => $this->settings,
            'access_manager' => $this->components['access'] ?? null,
            'portability' => $this->components['portability'] ?? null,
            'encryption' => $this->components['encryption'] ?? null,
            'caching' => $this->components['caching'] ?? null,
            'network' => $this->components['network'] ?? null,
            'api_security' => $this->components['api_security'] ?? null,
            // Add these security components:
            'rbac' => $this->components['rbac'] ?? null,
            'mfa' => $this->components['mfa'] ?? null,
            'security' => $this->components['security'] ?? null,
            'consent_types' => get_option('gdpr_consent_types', [])
        ]);
    }

    /**
     * Render audit log page
     */
    public function renderAuditLog() {
        if (!isset($this->components['template'])) {
            echo '<div class="wrap"><h1>' . esc_html__('GDPR Audit Log', 'wp-gdpr-framework') . '</h1>';
            echo '<p>' . esc_html__('Template component not initialized.', 'wp-gdpr-framework') . '</p></div>';
            return;
        }

        echo $this->components['template']->render('admin/audit-log', [
            'audit' => $this->components['audit'] ?? null,
            'stats' => $this->components['audit'] ? $this->components['audit']->getStats() : null
        ]);
    }
    
    /**
     * Render system status page
     */
    public function renderSystemStatus() {
        if (!isset($this->components['template'])) {
            echo '<div class="wrap"><h1>' . esc_html__('GDPR System Status', 'wp-gdpr-framework') . '</h1>';
            echo '<p>' . esc_html__('Template component not initialized.', 'wp-gdpr-framework') . '</p></div>';
            return;
        }
        
        $requirements_info = [];
        $requirements_summary = [];
        
        if (isset($this->components['requirements'])) {
            $requirements_info = $this->components['requirements']->checkAll();
            $requirements_summary = $this->components['requirements']->getSummary();
        }
        
        echo $this->components['template']->render('admin/system-status', [
            'requirements' => $this->components['requirements'] ?? null,
            'requirements_info' => $requirements_info,
            'requirements_summary' => $requirements_summary,
            'database_stats' => $this->database->getTableStatus(),
            'caching' => $this->components['caching'] ?? null,
            'network' => $this->components['network'] ?? null
        ]);
    }

    /**
     * Get component statistics
     */
    private function getStats() {
        $stats = [
            'total_consents' => 0,
            'active_consents' => 0,
            'pending_requests' => 0,
            'data_requests' => 0,
            'recent_exports' => 0
        ];
    
        try {
            if (isset($this->components['consent']) && 
                method_exists($this->components['consent'], 'getTotalConsents')) {
                $stats['total_consents'] = $this->components['consent']->getTotalConsents();
                $stats['active_consents'] = $this->components['consent']->getActiveConsents();
            }
    
            if (isset($this->components['portability']) && 
                method_exists($this->components['portability'], 'getPendingRequests')) {
                $requests = $this->components['portability']->getPendingRequests();
                $stats['pending_requests'] = is_array($requests) ? count($requests) : 0;
                $stats['data_requests'] = $stats['pending_requests'];
            }
            
            // Add caching stats if available
            if (isset($this->components['caching'])) {
                $stats['cache_info'] = $this->components['caching']->getCacheInfo();
            }
            
            // Add network stats if available
            if (isset($this->components['network'])) {
                $stats['network_info'] = $this->components['network']->getNetworkInfo();
            }
        } catch (\Exception $e) {
            error_log('GDPR Framework Stats Error: ' . $e->getMessage());
        }
    
        return $stats;
    }

    public function getDatabase() {
        return $this->database;
    }

    public static function activate() {
        $instance = self::getInstance();
        if (!current_user_can('activate_plugins')) {
            return;
        }

        $instance->getDatabase()->createTables();
        $instance->settings->setDefaults();
        
        // Clear any cached data
        wp_cache_flush();
        
        // Schedule cron jobs
        $instance->setupCronJobs();
        
        flush_rewrite_rules();
    }

    /**
     * Setup cleanup schedule
     */
    private function setupCleanupSchedule() {
        if (!wp_next_scheduled('gdpr_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'gdpr_daily_cleanup');
        }
        
        // Add weekly maintenance tasks
        if (!wp_next_scheduled('gdpr_weekly_maintenance')) {
            wp_schedule_event(time(), 'weekly', 'gdpr_weekly_maintenance');
        }

        add_action('gdpr_daily_cleanup', [$this, 'performCleanup']);
        add_action('gdpr_weekly_maintenance', [$this, 'performMaintenance']);
    }

    /**
     * Perform cleanup tasks
     */
    public function performCleanup() {
        try {
            // Clean up audit logs
            if (isset($this->components['audit'])) {
                $this->components['audit']->cleanupOldLogs();
            }

            // Clean up expired exports
            if (isset($this->components['portability'])) {
                $this->components['portability']->cleanupExpiredExports();
            }

            // Log cleanup activity
            if (isset($this->components['audit'])) {
                $this->components['audit']->log(
                    0,
                    'maintenance',
                    __('Automated cleanup performed', 'wp-gdpr-framework'),
                    'low'
                );
            }

            update_option('gdpr_last_cleanup', current_time('mysql'));
        } catch (\Exception $e) {
            error_log('GDPR Framework Cleanup Error: ' . $e->getMessage());
        }
    }
    
    /**
     * Perform weekly maintenance tasks
     */
    public function performMaintenance() {
        try {
            // Optimize database tables
            $optimized_tables = $this->database->optimizeTables();
            
            // Log maintenance activity
            if (isset($this->components['audit'])) {
                $this->components['audit']->log(
                    0,
                    'database_maintenance',
                    sprintf(
                        __('Database tables optimized: %s', 'wp-gdpr-framework'),
                        implode(', ', $optimized_tables)
                    ),
                    'low'
                );
            }
            
            // Check if key rotation is due
            if (isset($this->components['encryption'])) {
                $this->components['encryption']->checkAndRotateKey();
            }
            
            update_option('gdpr_last_maintenance', current_time('mysql'));
        } catch (\Exception $e) {
            error_log('GDPR Framework Maintenance Error: ' . $e->getMessage());
        }
    }

    /**
     * Add cleanup settings
     */
    private function addCleanupSettings() {
        add_settings_section(
            'gdpr_cleanup_section',
            __('Cleanup Settings', 'wp-gdpr-framework'),
            [$this, 'renderCleanupSection'],
            'gdpr_framework_settings'
        );

        register_setting('gdpr_framework_settings', 'gdpr_cleanup_time', [
            'type' => 'string',
            'default' => '00:00',
            'sanitize_callback' => 'sanitize_text_field'
        ]);
    }

    /**
     * Get cleanup status
     */
    public function getCleanupStatus() {
        $next_cleanup = wp_next_scheduled('gdpr_daily_cleanup');
        $next_maintenance = wp_next_scheduled('gdpr_weekly_maintenance');
        
        return [
            'next_run' => $next_cleanup ? date_i18n(
                get_option('date_format') . ' ' . get_option('time_format'),
                $next_cleanup
            ) : __('Not scheduled', 'wp-gdpr-framework'),
            'last_run' => get_option('gdpr_last_cleanup', __('Never', 'wp-gdpr-framework')),
            'next_maintenance' => $next_maintenance ? date_i18n(
                get_option('date_format') . ' ' . get_option('time_format'),
                $next_maintenance
            ) : __('Not scheduled', 'wp-gdpr-framework'),
            'last_maintenance' => get_option('gdpr_last_maintenance', __('Never', 'wp-gdpr-framework'))
        ];
    }

    /**
     * Manually trigger cleanup
     */
    public function manualCleanup() {
        if (!current_user_can('manage_options')) {
            return false;
        }

        $this->performCleanup();
        return true;
    }
    
    /**
     * Manually trigger maintenance
     */
    public function manualMaintenance() {
        if (!current_user_can('manage_options')) {
            return false;
        }

        $this->performMaintenance();
        return true;
    }

    /**
     * Get specific component
     */
    public function getComponent($name) {
        return $this->components[$name] ?? null;
    }

    /**
     * Display initialization error
     */
    public function displayInitializationError() {
        echo '<div class="notice notice-error"><p>' . 
             esc_html__('GDPR Framework failed to initialize properly. Please check the error logs.', 'wp-gdpr-framework') . 
             '</p></div>';
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        if (!current_user_can('activate_plugins')) {
            return;
        }

        wp_clear_scheduled_hook('gdpr_daily_cleanup');
        wp_clear_scheduled_hook('gdpr_weekly_maintenance');
        flush_rewrite_rules();
    }

    /**
     * Register custom cron schedules for reports
     */
    public function registerCronSchedules($schedules) {
        // Add monthly schedule if not exists
        if (!isset($schedules['monthly'])) {
            $schedules['monthly'] = array(
                'interval' => 30 * DAY_IN_SECONDS,
                'display' => __('Once a month', 'wp-gdpr-framework')
            );
        }
        
        // Add quarterly schedule if not exists
        if (!isset($schedules['quarterly'])) {
            $schedules['quarterly'] = array(
                'interval' => 90 * DAY_IN_SECONDS,
                'display' => __('Once every three months', 'wp-gdpr-framework')
            );
        }
        
        return $schedules;
    }

    /**
     * Setup cron jobs for the plugin
     */
    public function setupCronJobs() {
        // Add filter for custom cron schedules
        add_filter('cron_schedules', [$this, 'registerCronSchedules']);
        
        // Setup daily cleanup task
        if (!wp_next_scheduled('gdpr_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'gdpr_daily_cleanup');
        }
        
        // Setup weekly maintenance task
        if (!wp_next_scheduled('gdpr_weekly_maintenance')) {
            wp_schedule_event(time(), 'weekly', 'gdpr_weekly_maintenance');
        }
        
        // Setup scheduled reports based on settings
        $this->setupScheduledReports();
    }

    /**
     * Setup scheduled reports based on settings
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
            
            // Add action handler for scheduled reports
            add_action('gdpr_scheduled_report', function() {
                if (isset($this->components['reports'])) {
                    $this->components['reports']->generateScheduledReports();
                }
            });
        }
    }
    
    /**
     * Handle admin-post.php actions
     */
    public function handleAdminPostActions() {
        $action = $_REQUEST['action'] ?? '';
        
        if ($action === 'gdpr_generate_report' && isset($this->components['reports'])) {
            $this->components['reports']->handleReportGeneration();
        }
    }

    /**
     * Verify database tables exist
     *
     * @return bool
     */
    public function verifyTables() {
        if (!$this->database) {
            return false;
        }
        return $this->database->verifyTables();
    }
     
    /**
     * Render cleanup section
     */
    public function renderCleanupSection() {
        echo '<p>' . esc_html__('Configure automated data cleanup settings.', 'wp-gdpr-framework') . '</p>';
    }
}
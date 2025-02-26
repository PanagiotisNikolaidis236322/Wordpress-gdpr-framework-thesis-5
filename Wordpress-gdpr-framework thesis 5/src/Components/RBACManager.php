<?php
namespace GDPRFramework\Components;

/**
 * Role-Based Access Control Manager
 * 
 * Implements a multi-layered RBAC system as described in the security implementation
 * chapter. The system has 4 primary layers:
 * 1. Admin Controls - Restricts GDPR settings access
 * 2. User Permissions - Users can only modify their own data
 * 3. Plugin & API Security - Blocks unauthorized third-party tracking
 * 4. Time-Based Access - Enforces session timeouts and auto-logout
 */
class RBACManager {
    private $db;
    private $settings;
    private $session_duration = 3600; // 1 hour default
    private $session_table;
    private $inactive_timeout = 900; // 15 minutes default
    private $gdpr_roles = [
        'gdpr_admin' => [
            'name' => 'GDPR Administrator',
            'capabilities' => [
                'manage_gdpr_settings',
                'access_gdpr_reports',
                'access_gdpr_audit_log',
                'process_data_requests',
                'view_all_consents',
                'reset_user_mfa',
                'manage_gdpr_audit',
                'view_gdpr_dashboard'
            ]
        ],
        'gdpr_officer' => [
            'name' => 'GDPR Data Protection Officer',
            'capabilities' => [
                'access_gdpr_reports',
                'access_gdpr_audit_log',
                'process_data_requests',
                'view_all_consents',
                'view_gdpr_dashboard'
            ]
        ],
        'gdpr_processor' => [
            'name' => 'GDPR Data Processor',
            'capabilities' => [
                'process_data_requests',
                'view_assigned_consents',
                'view_gdpr_dashboard'
            ]
        ]
    ];

    public function __construct($database, $settings) {
        global $wpdb;
        $this->db = $database;
        $this->settings = $settings;
        $this->session_table = $wpdb->prefix . 'gdpr_user_sessions';
        
        // Initialize database tables
        $this->createSessionTable();
        
        // Load settings
        $this->session_duration = get_option('gdpr_session_duration', 3600);
        $this->inactive_timeout = get_option('gdpr_inactive_timeout', 900);
        
        // Initialize hooks
        $this->initializeHooks();
    }

    /**
     * Initialize hooks for RBAC system
     */
    private function initializeHooks() {
        // Add hooks for session management
        add_action('init', [$this, 'initSession']);
        add_action('wp_login', [$this, 'createUserSession'], 10, 2);
        add_action('wp_logout', [$this, 'destroyUserSession']);
        add_action('clear_auth_cookie', [$this, 'destroyUserSession']);
        
        // Add hooks for capability management
        add_action('init', [$this, 'registerGDPRRoles']);
        add_filter('user_has_cap', [$this, 'filterUserCapabilities'], 10, 4);
        
        // Add hooks for admin menu access control
        add_action('admin_menu', [$this, 'restrictAdminMenuAccess'], 999);
        add_action('admin_init', [$this, 'restrictAdminPageAccess']);
        
        // Add hooks for time-based access control
        add_action('admin_enqueue_scripts', [$this, 'enqueueInactivityMonitor']);
        add_action('wp_ajax_gdpr_update_session_activity', [$this, 'updateSessionActivity']);
        add_action('wp_ajax_gdpr_check_session_validity', [$this, 'checkSessionValidity']);
        
        // Add hooks for settings
        add_action('admin_init', [$this, 'registerSettings']);
        
        // Add hooks for cleanup
        add_action('wp_scheduled_delete', [$this, 'cleanupExpiredSessions']);
        add_action('gdpr_daily_cleanup', [$this, 'cleanupExpiredSessions']);
    }
    
    /**
     * Create session table if it doesn't exist
     */
    private function createSessionTable() {
        global $wpdb;
        
        $table_name = $this->session_table;
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            session_id varchar(64) NOT NULL,
            ip_address varchar(45) NOT NULL,
            user_agent text NOT NULL,
            created datetime DEFAULT CURRENT_TIMESTAMP,
            last_activity datetime DEFAULT CURRENT_TIMESTAMP,
            expires datetime NOT NULL,
            data longtext,
            PRIMARY KEY (id),
            UNIQUE KEY session_id (session_id),
            KEY user_id (user_id),
            KEY expires (expires)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    /**
     * Register settings for RBAC system
     */
    public function registerSettings() {
        // Add settings for session duration
        register_setting('gdpr_framework_settings', 'gdpr_session_duration', [
            'type' => 'integer',
            'default' => 3600,
            'sanitize_callback' => [$this, 'sanitizeSessionDuration']
        ]);
        
        // Add settings for inactivity timeout
        register_setting('gdpr_framework_settings', 'gdpr_inactive_timeout', [
            'type' => 'integer',
            'default' => 900,
            'sanitize_callback' => [$this, 'sanitizeInactiveTimeout']
        ]);
        
        // Add settings section
        add_settings_section(
            'gdpr_rbac_section',
            __('Access Control Settings', 'wp-gdpr-framework'),
            [$this, 'renderRBACSection'],
            'gdpr_framework_settings'
        );
        
        // Add settings fields
        add_settings_field(
            'gdpr_session_duration',
            __('Session Duration', 'wp-gdpr-framework'),
            [$this, 'renderSessionDurationField'],
            'gdpr_framework_settings',
            'gdpr_rbac_section'
        );
        
        add_settings_field(
            'gdpr_inactive_timeout',
            __('Inactivity Timeout', 'wp-gdpr-framework'),
            [$this, 'renderInactiveTimeoutField'],
            'gdpr_framework_settings',
            'gdpr_rbac_section'
        );
        
        add_settings_field(
            'gdpr_role_management',
            __('GDPR Role Management', 'wp-gdpr-framework'),
            [$this, 'renderRoleManagementField'],
            'gdpr_framework_settings',
            'gdpr_rbac_section'
        );
    }
    
    /**
     * Render RBAC settings section
     */
    public function renderRBACSection() {
        echo '<p>' . 
             esc_html__('Configure role-based access control and session settings for GDPR-related operations.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render session duration field
     */
    public function renderSessionDurationField() {
        $duration = get_option('gdpr_session_duration', 3600);
        
        echo '<input type="number" id="gdpr_session_duration" name="gdpr_session_duration" value="' . 
             esc_attr($duration) . '" min="900" max="86400" step="300" class="small-text"> ' . 
             esc_html__('seconds', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('Maximum duration of a user session before requiring re-authentication. Default: 1 hour (3600 seconds).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render inactivity timeout field
     */
    public function renderInactiveTimeoutField() {
        $timeout = get_option('gdpr_inactive_timeout', 900);
        
        echo '<input type="number" id="gdpr_inactive_timeout" name="gdpr_inactive_timeout" value="' . 
             esc_attr($timeout) . '" min="300" max="3600" step="60" class="small-text"> ' . 
             esc_html__('seconds', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('Time of inactivity before a user is automatically logged out. Default: 15 minutes (900 seconds).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render role management field
     */
    public function renderRoleManagementField() {
        // Get all users with GDPR roles
        $gdpr_roles = array_keys($this->gdpr_roles);
        $users_with_roles = [];
        
        foreach ($gdpr_roles as $role) {
            $users = get_users(['role' => $role]);
            foreach ($users as $user) {
                $users_with_roles[$role][] = $user;
            }
        }
        
        echo '<div class="gdpr-role-management">';
        
        foreach ($this->gdpr_roles as $role_key => $role_data) {
            echo '<div class="gdpr-role-section">';
            echo '<h4>' . esc_html($role_data['name']) . '</h4>';
            
            // Show users with this role
            echo '<div class="gdpr-role-users">';
            if (!empty($users_with_roles[$role_key])) {
                echo '<ul>';
                foreach ($users_with_roles[$role_key] as $user) {
                    echo '<li>' . esc_html($user->display_name) . ' (' . esc_html($user->user_login) . ')</li>';
                }
                echo '</ul>';
            } else {
                echo '<p>' . esc_html__('No users assigned to this role.', 'wp-gdpr-framework') . '</p>';
            }
            echo '</div>';
            
            // Add capability list
            echo '<div class="gdpr-role-capabilities">';
            echo '<p><strong>' . esc_html__('Capabilities:', 'wp-gdpr-framework') . '</strong></p>';
            echo '<ul class="gdpr-capabilities-list">';
            foreach ($role_data['capabilities'] as $cap) {
                echo '<li>' . esc_html($this->formatCapabilityName($cap)) . '</li>';
            }
            echo '</ul>';
            echo '</div>';
            
            echo '</div>';
        }
        
        // Add button to manage roles in User screen
        echo '<p><a href="' . esc_url(admin_url('users.php')) . '" class="button">' . 
             esc_html__('Manage User Roles', 'wp-gdpr-framework') . 
             '</a></p>';
        
        echo '</div>';
    }
    
    /**
     * Format capability name for display
     */
    private function formatCapabilityName($capability) {
        return ucfirst(str_replace('_', ' ', $capability));
    }
    
    /**
     * Sanitize session duration setting
     */
    public function sanitizeSessionDuration($duration) {
        $duration = absint($duration);
        
        // Minimum 15 minutes, maximum 24 hours
        if ($duration < 900) {
            return 900;
        }
        
        if ($duration > 86400) {
            return 86400;
        }
        
        return $duration;
    }
    
    /**
     * Sanitize inactive timeout setting
     */
    public function sanitizeInactiveTimeout($timeout) {
        $timeout = absint($timeout);
        
        // Minimum 5 minutes, maximum 1 hour
        if ($timeout < 300) {
            return 300;
        }
        
        if ($timeout > 3600) {
            return 3600;
        }
        
        return $timeout;
    }
    
    /**
     * Register GDPR-specific roles
     */
    public function registerGDPRRoles() {
        foreach ($this->gdpr_roles as $role_key => $role_data) {
            // Check if role exists
            if (!get_role($role_key)) {
                // Add role with capabilities
                add_role(
                    $role_key,
                    $role_data['name'],
                    array_fill_keys($role_data['capabilities'], true)
                );
            } else {
                // Update existing role capabilities
                $role = get_role($role_key);
                foreach ($role_data['capabilities'] as $cap) {
                    $role->add_cap($cap);
                }
            }
        }
        
        // Add GDPR capabilities to administrator role
        $admin_role = get_role('administrator');
        if ($admin_role) {
            foreach ($this->gdpr_roles['gdpr_admin']['capabilities'] as $cap) {
                $admin_role->add_cap($cap);
            }
        }
    }
    
    /**
     * Filter user capabilities for GDPR-specific operations
     */
    public function filterUserCapabilities($allcaps, $caps, $args, $user) {
        // If not checking a specific capability, return
        if (empty($args[0])) {
            return $allcaps;
        }
        
        // Check for GDPR-specific capabilities
        if (0 === strpos($args[0], 'gdpr_') || 0 === strpos($args[0], 'manage_gdpr_')) {
            // Get the current user ID (being checked)
            $user_id = $args[1] ?? 0;
            
            // For data access capabilities, enforce user can only access their own data
            if ($args[0] === 'gdpr_access_own_data' && $user_id === get_current_user_id()) {
                $allcaps[$args[0]] = true;
            }
            
            // Check for time-based restrictions
            if ($this->hasTimedOut($user_id)) {
                $allcaps[$args[0]] = false;
            }
        }
        
        return $allcaps;
    }
    
    /**
     * Restrict access to Admin menu items based on capabilities
     */
    public function restrictAdminMenuAccess() {
        global $menu, $submenu;
        
        // Check permissions for GDPR-related menu items
        if (isset($submenu['gdpr-framework'])) {
            foreach ($submenu['gdpr-framework'] as $key => $item) {
                // Skip if not set
                if (!isset($item[1])) {
                    continue;
                }
                
                $capability = $item[1];
                
                // Map page slugs to specific capabilities
                switch ($item[2]) {
                    case 'gdpr-framework':
                        $capability = 'view_gdpr_dashboard';
                        break;
                    case 'gdpr-framework-settings':
                        $capability = 'manage_gdpr_settings';
                        break;
                    case 'gdpr-framework-audit':
                        $capability = 'access_gdpr_audit_log';
                        break;
                    case 'gdpr-framework-system':
                        $capability = 'manage_gdpr_settings';
                        break;
                }
                
                // Remove menu item if user doesn't have the capability
                if (!current_user_can($capability)) {
                    unset($submenu['gdpr-framework'][$key]);
                }
            }
        }
    }
    
    /**
     * Restrict access to admin pages based on capabilities
     */
    public function restrictAdminPageAccess() {
        $screen = get_current_screen();
        
        if (!$screen) {
            return;
        }
        
        // Map screen IDs to capabilities
        $page_caps = [
            'toplevel_page_gdpr-framework' => 'view_gdpr_dashboard',
            'gdpr-framework_page_gdpr-framework-settings' => 'manage_gdpr_settings',
            'gdpr-framework_page_gdpr-framework-audit' => 'access_gdpr_audit_log',
            'gdpr-framework_page_gdpr-framework-system' => 'manage_gdpr_settings'
        ];
        
        // Check if current screen is restricted
        if (isset($page_caps[$screen->id]) && !current_user_can($page_caps[$screen->id])) {
            wp_die(
                __('You do not have sufficient permissions to access this page.', 'wp-gdpr-framework'),
                __('Access Denied', 'wp-gdpr-framework'),
                ['response' => 403, 'back_link' => true]
            );
        }
    }
    
    /**
     * Initialize user session
     */
    public function initSession() {
        if (!is_user_logged_in()) {
            return;
        }
        
        // Start session if not already started
        if (!session_id() && !headers_sent()) {
            // Set secure session cookies
            if (version_compare(PHP_VERSION, '7.3.0', '>=')) {
                session_set_cookie_params([
                    'lifetime' => $this->session_duration,
                    'path' => COOKIEPATH,
                    'domain' => COOKIE_DOMAIN,
                    'secure' => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]);
            } else {
                // For older PHP versions
                session_set_cookie_params(
                    $this->session_duration,
                    COOKIEPATH,
                    COOKIE_DOMAIN,
                    is_ssl(),
                    true
                );
            }
            
            session_start();
        }
        
        // Check if user has an active session
        $user_id = get_current_user_id();
        $session_id = session_id();
        
        if (empty($session_id)) {
            return;
        }
        
        // Check if this session is in the database
        $session = $this->getSession($session_id);
        
        if (!$session) {
            // Create a new session record
            $this->createSession($user_id, $session_id);
        } else {
            // Verify session belongs to current user
            if ($session->user_id != $user_id) {
                // Session hijacking attempt - destroy session
                $this->destroyUserSession();
                wp_die(
                    __('Session validation failed. Please log in again.', 'wp-gdpr-framework'),
                    __('Security Error', 'wp-gdpr-framework'),
                    ['response' => 403, 'back_link' => true]
                );
            }
            
            // Check if session has expired
            if (strtotime($session->expires) < time()) {
                // Session expired - destroy it
                $this->destroyUserSession();
                wp_redirect(wp_login_url(admin_url()));
                exit;
            }
            
            // Check for inactivity timeout
            if (strtotime($session->last_activity) + $this->inactive_timeout < time()) {
                // Session inactive - destroy it
                $this->destroyUserSession();
                wp_redirect(add_query_arg('timeout', '1', wp_login_url(admin_url())));
                exit;
            }
            
            // Update last activity
            $this->updateSessionActivity();
        }
    }
    
    /**
     * Create user session on login
     */
    public function createUserSession($username, $user) {
        if (!$user instanceof \WP_User) {
            return;
        }
        
        // Ensure we have a session
        if (!session_id() && !headers_sent()) {
            session_start();
        }
        
        $session_id = session_id();
        
        if (empty($session_id)) {
            return;
        }
        
        // Create a session record
        $this->createSession($user->ID, $session_id);
    }
    
    /**
     * Create a session record in the database
     */
    private function createSession($user_id, $session_id) {
        global $wpdb;
        
        // Calculate expiry time
        $expires = date('Y-m-d H:i:s', time() + $this->session_duration);
        
        // Insert new session
        $wpdb->insert(
            $this->session_table,
            [
                'user_id' => $user_id,
                'session_id' => $session_id,
                'ip_address' => $this->getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                'created' => current_time('mysql'),
                'last_activity' => current_time('mysql'),
                'expires' => $expires,
                'data' => serialize([])
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );
        
        // Store session data
        $_SESSION['gdpr_user_id'] = $user_id;
        $_SESSION['gdpr_session_created'] = time();
        $_SESSION['gdpr_session_expires'] = time() + $this->session_duration;
    }
    
    /**
     * Get a session by ID
     */
    private function getSession($session_id) {
        global $wpdb;
        
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->session_table} WHERE session_id = %s",
            $session_id
        ));
    }
    
    /**
     * Update session last activity timestamp
     */
    public function updateSessionActivity() {
        if (!is_user_logged_in() || !session_id()) {
            return false;
        }
        
        global $wpdb;
        
        // Update last activity timestamp
        $updated = $wpdb->update(
            $this->session_table,
            ['last_activity' => current_time('mysql')],
            ['session_id' => session_id()],
            ['%s'],
            ['%s']
        );
        
        // Handle AJAX request if applicable
        if (defined('DOING_AJAX') && DOING_AJAX) {
            wp_send_json_success(['updated' => (bool)$updated]);
        }
        
        return (bool)$updated;
    }
    
    /**
     * Check if session is still valid via AJAX
     */
    public function checkSessionValidity() {
        if (!is_user_logged_in() || !session_id()) {
            wp_send_json_error(['valid' => false, 'message' => 'No active session']);
        }
        
        $session = $this->getSession(session_id());
        
        if (!$session) {
            wp_send_json_error(['valid' => false, 'message' => 'Session not found']);
        }
        
        // Check if session has expired
        if (strtotime($session->expires) < time()) {
            wp_send_json_error(['valid' => false, 'message' => 'Session expired']);
        }
        
        // Check for inactivity timeout
        if (strtotime($session->last_activity) + $this->inactive_timeout < time()) {
            wp_send_json_error(['valid' => false, 'message' => 'Session timed out due to inactivity']);
        }
        
        wp_send_json_success([
            'valid' => true, 
            'expires' => strtotime($session->expires),
            'timeout' => strtotime($session->last_activity) + $this->inactive_timeout
        ]);
    }
    
    /**
     * Destroy user session on logout
     */
    public function destroyUserSession() {
        if (!session_id() && !headers_sent()) {
            session_start();
        }
        
        $session_id = session_id();
        
        if ($session_id) {
            // Remove session from database
            global $wpdb;
            $wpdb->delete(
                $this->session_table,
                ['session_id' => $session_id],
                ['%s']
            );
            
            // Destroy PHP session
            session_destroy();
        }
    }
    
    /**
     * Check if user session has timed out
     */
    private function hasTimedOut($user_id) {
        if (!is_user_logged_in() || !session_id()) {
            return true;
        }
        
        // If not checking the current user, we can't determine timeout
        if ($user_id != get_current_user_id()) {
            return false;
        }
        
        // Get session data
        $session = $this->getSession(session_id());
        
        if (!$session) {
            return true;
        }
        
        // Check if session has expired
        if (strtotime($session->expires) < time()) {
            return true;
        }
        
        // Check for inactivity timeout
        if (strtotime($session->last_activity) + $this->inactive_timeout < time()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Enqueue inactivity monitor JavaScript
     */
    public function enqueueInactivityMonitor() {
        // Only enqueue on GDPR framework pages
        $screen = get_current_screen();
        if (!$screen || strpos($screen->id, 'gdpr-framework') === false) {
            return;
        }
        
        wp_enqueue_script(
            'gdpr-inactivity-monitor',
            GDPR_FRAMEWORK_URL . 'assets/js/inactivity-monitor.js',
            ['jquery'],
            GDPR_FRAMEWORK_VERSION,
            true
        );
        
        // Pass settings to script
        wp_localize_script(
            'gdpr-inactivity-monitor',
            'gdprInactivitySettings',
            [
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('gdpr_session_nonce'),
                'inactiveTimeout' => $this->inactive_timeout,
                'warningTime' => 60, // Show warning 60 seconds before timeout
                'checkInterval' => 30 // Check every 30 seconds
            ]
        );
    }
    
    /**
     * Clean up expired sessions
     */
    public function cleanupExpiredSessions() {
        global $wpdb;
        
        // Delete expired sessions
        $wpdb->query("DELETE FROM {$this->session_table} WHERE expires < NOW()");
        
        // Log the cleanup
        $deleted = $wpdb->rows_affected;
        do_action('gdpr_sessions_cleaned', $deleted);
        
        return $deleted;
    }
    
    /**
     * Get client IP address with proxy support
     */
    private function getClientIP() {
        $ip = '';
        
        // Check for various proxy headers
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
     * Check if current user has a specific GDPR capability
     * 
     * @param string $capability The capability to check
     * @return boolean Whether the user has the capability
     */
    public function currentUserCan($capability) {
        if (!is_user_logged_in()) {
            return false;
        }
        
        // For regular capabilities, use WordPress core function
        if (current_user_can($capability)) {
            // Also check for session timeout
            if (!$this->hasTimedOut(get_current_user_id())) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get active user sessions
     * 
     * @param int|null $user_id Optional user ID to filter by
     * @return array Active sessions
     */
    public function getActiveSessions($user_id = null) {
        global $wpdb;
        
        $query = "SELECT * FROM {$this->session_table} WHERE expires > NOW()";
        $params = [];
        
        if ($user_id) {
            $query .= " AND user_id = %d";
            $params[] = $user_id;
        }
        
        $query .= " ORDER BY last_activity DESC";
        
        if (!empty($params)) {
            $query = $wpdb->prepare($query, $params);
        }
        
        return $wpdb->get_results($query);
    }
    
    /**
     * Terminate a specific session
     * 
     * @param string $session_id The session ID to terminate
     * @return boolean Success status
     */
    public function terminateSession($session_id) {
        if (!current_user_can('gdpr_admin')) {
            return false;
        }
        
        global $wpdb;
        
        // Get session data for logging
        $session = $this->getSession($session_id);
        
        if (!$session) {
            return false;
        }
        
        // Delete the session
        $result = $wpdb->delete(
            $this->session_table,
            ['session_id' => $session_id],
            ['%s']
        );
        
        if ($result) {
            // Log the termination
            do_action('gdpr_session_terminated', get_current_user_id(), [
                'terminated_user_id' => $session->user_id,
                'session_id' => $session_id,
                'ip_address' => $session->ip_address
            ]);
        }
        
        return (bool)$result;
    }
    
    /**
     * Terminate all sessions for a user
     * 
     * @param int $user_id The user ID to terminate sessions for
     * @return int Number of sessions terminated
     */
    public function terminateUserSessions($user_id) {
        if (!current_user_can('gdpr_admin') && get_current_user_id() != $user_id) {
            return 0;
        }
        
        global $wpdb;
        
        // Delete all sessions for user
        $result = $wpdb->delete(
            $this->session_table,
            ['user_id' => $user_id],
            ['%d']
        );
        
        if ($result) {
            // Log the termination
            do_action('gdpr_all_sessions_terminated', get_current_user_id(), [
                'terminated_user_id' => $user_id,
                'count' => $result
            ]);
        }
        
        return (int)$result;
    }
}
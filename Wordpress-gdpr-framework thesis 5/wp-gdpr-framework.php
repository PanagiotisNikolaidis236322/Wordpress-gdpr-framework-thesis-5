<?php
/**
 * Plugin Name: WordPress GDPR Framework
 * Plugin URI: https://example.com/wordpress-gdpr-framework
 * Description: A comprehensive GDPR compliance solution
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: Your Name
 * License: GPL v2 or later
 * Text Domain: wp-gdpr-framework
 */

if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('GDPR_FRAMEWORK_VERSION', '1.0.0');
define('GDPR_FRAMEWORK_PATH', plugin_dir_path(__FILE__));
define('GDPR_FRAMEWORK_URL', plugin_dir_url(__FILE__));
define('GDPR_FRAMEWORK_TEMPLATE_PATH', plugin_dir_path(__FILE__) . 'templates/');
define('GDPR_FRAMEWORK_PUBLIC_TEMPLATE_PATH', GDPR_FRAMEWORK_TEMPLATE_PATH . 'public/');
define('GDPR_FRAMEWORK_ADMIN_TEMPLATE_PATH', GDPR_FRAMEWORK_TEMPLATE_PATH . 'admin/');

// Verify required files exist
function gdpr_framework_verify_files() {
    $required_files = [
        'src/Core/Database.php',
        'src/Core/Settings.php',
        'src/Core/GDPRFramework.php',
        'src/Components/UserConsentManager.php',
        'src/Components/TemplateRenderer.php',
        'src/Components/DataEncryptionManager.php',
        'src/Components/DataPortabilityManager.php',
        'src/Components/LoggingAuditManager.php',
        'src/Components/AccessControlManager.php',
        'src/Components/ComplianceReportManager.php',
        'src/Components/CachingManager.php',
        'src/Components/SystemRequirementsChecker.php',
        'src/Components/MultiFactorAuthManager.php',
        'src/Components/RBACManager.php',
        'src/Components/SecurityEnforcer.php'
    ];
    
    $missing_files = [];
    foreach ($required_files as $file) {
        if (!file_exists(GDPR_FRAMEWORK_PATH . $file)) {
            $missing_files[] = $file;
        }
    }
    
    if (!empty($missing_files)) {
        error_log('GDPR Framework - Missing required files: ' . implode(', ', $missing_files));
        return false;
    }
    
    return true;
}


if (defined('WP_DEBUG') && WP_DEBUG) {
    add_action('wp_ajax_update_user_consent', function() {
        error_log('GDPR Debug: AJAX consent update triggered');
        error_log('POST data: ' . print_r($_POST, true));
    }, 5);
}

// Autoloader
function gdpr_framework_autoloader($class) {
    $prefix = 'GDPRFramework\\';
    $length = strlen($prefix);
    
    if (strncmp($prefix, $class, $length) !== 0) {
        return;
    }

    $relative_class = substr($class, $length);
    $file = GDPR_FRAMEWORK_PATH . 'src/' . str_replace('\\', '/', $relative_class) . '.php';
    
    if (file_exists($file)) {
        require_once $file;
    }
}

spl_autoload_register('gdpr_framework_autoloader');

// Register activation/deactivation hooks
register_activation_hook(__FILE__, function() {
    try {
        if (!gdpr_framework_verify_files()) {
            throw new \Exception('Required files are missing. Please reinstall the plugin.');
        }
        
        // First check system requirements
        $requirements = new \GDPRFramework\Components\SystemRequirementsChecker();
        $results = $requirements->checkAll();
        $summary = $requirements->getSummary();
        
        // If we have any errors, don't activate
        if ($summary['error'] > 0) {
            $error_messages = [];
            foreach ($results as $result) {
                if ($result['status'] === 'error') {
                    $error_messages[] = $result['message'];
                }
            }
            throw new \Exception('System requirements not met: ' . implode(', ', $error_messages));
        }
        
        global $wpdb;
        
        // Create database tables without dropping existing ones
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
        $db = $framework->getDatabase();
        if (!isset($db) || !is_object($db)) {
            throw new \Exception('Database initialization failed');
        }

        // Create tables only if they don't exist
        $db->createTables();
        error_log('GDPR Framework - Tables created or updated');
        
        // Set default settings
        $framework->settings->setDefaults();

        // Initialize necessary components explicitly
        // Add default consent types if needed
        try {
            // Force initialization of consent component
            if (!isset($framework->components['consent'])) {
                $framework->components['consent'] = new \GDPRFramework\Components\UserConsentManager(
                    $framework->database,
                    $framework->settings
                );
            }
            
            // Add default consent types
            $consent = $framework->getComponent('consent');
            if ($consent) {
                $consent->addDefaultConsentTypes();
            }
            
            // Initialize caching component
            if (!isset($framework->components['caching'])) {
                $framework->components['caching'] = new \GDPRFramework\Components\CachingManager(
                    $framework->settings
                );
            }
        } catch (\Exception $e) {
            error_log('GDPR Framework - Component initialization error: ' . $e->getMessage());
            // Continue with activation - this is not a critical error
        }

        // Setup cron jobs
        if (method_exists($framework, 'setupCronJobs')) {
            $framework->setupCronJobs();
        }

        // Clear any cached data
        wp_cache_flush();
        
        flush_rewrite_rules();
        
        error_log('GDPR Framework - Activation completed successfully');
    } catch (\Exception $e) {
        error_log('GDPR Framework Activation Error: ' . $e->getMessage());
        wp_die('GDPR Framework activation failed: ' . esc_html($e->getMessage()));
    }
});


register_deactivation_hook(__FILE__, ['\GDPRFramework\Core\GDPRFramework', 'deactivate']);

function gdpr_framework_init() {
    try {
        // Verify files exist
        if (!gdpr_framework_verify_files()) {
            add_action('admin_notices', function() {
                echo '<div class="notice notice-error"><p>' . 
                     esc_html__('GDPR Framework: Required files are missing. Please reinstall the plugin.', 'wp-gdpr-framework') . 
                     '</p></div>';
            });
            return;
        }

        // Initialize framework
        $framework = \GDPRFramework\Core\GDPRFramework::getInstance();

        // Ensure security components are initialized
        add_action('init', function() use ($framework) {
            // Force initialization of security components if needed
            if (!$framework->getComponent('rbac')) {
                $framework->components['rbac'] = new \GDPRFramework\Components\RBACManager(
                    $framework->database,
                    $framework->settings
                );
            }
            
            if (!$framework->getComponent('mfa')) {
                $framework->components['mfa'] = new \GDPRFramework\Components\MultiFactorAuthManager(
                    $framework->database,
                    $framework->settings
                );
            }
            
            if (!$framework->getComponent('security')) {
                $framework->components['security'] = new \GDPRFramework\Components\SecurityEnforcer(
                    $framework->database,
                    $framework->settings
                );
            }
        }, 5); // Priority 5 to run early
        
        // Add system requirements checker to dashboard
        add_action('admin_init', function() {
            $requirements = new \GDPRFramework\Components\SystemRequirementsChecker();
            $results = $requirements->checkAll();
            $summary = $requirements->getSummary();
            
            // Show admin notice if not all requirements are met
            if ($summary['error'] > 0 || $summary['warning'] > 0) {
                add_action('admin_notices', function() use ($summary) {
                    $class = $summary['error'] > 0 ? 'notice-error' : 'notice-warning';
                    echo '<div class="notice ' . esc_attr($class) . '">';
                    echo '<p><strong>' . esc_html__('GDPR Framework - System Requirements Check:', 'wp-gdpr-framework') . '</strong> ';
                    
                    if ($summary['error'] > 0) {
                        echo esc_html(sprintf(
                            __('%d critical requirements not met. Please check the GDPR dashboard for details.', 'wp-gdpr-framework'),
                            $summary['error']
                        ));
                    } else {
                        echo esc_html(sprintf(
                            __('%d warnings found. Consider upgrading your system for optimal performance.', 'wp-gdpr-framework'),
                            $summary['warning']
                        ));
                    }
                    
                    echo ' <a href="' . esc_url(admin_url('admin.php?page=gdpr-framework')) . '">' . 
                         esc_html__('View Details', 'wp-gdpr-framework') . '</a>';
                    echo '</p></div>';
                });
            }
        });
        
        // Verify database tables
        if (!$framework->verifyTables()) {
            add_action('admin_notices', function() {
                echo '<div class="notice notice-error"><p>' . 
                     esc_html__('GDPR Framework: Database tables are missing. Please deactivate and reactivate the plugin.', 'wp-gdpr-framework') . 
                     '<button class="button button-small" id="gdpr-repair-tables">' . 
                     esc_html__('Attempt Repair', 'wp-gdpr-framework') . '</button>' .
                     '</p></div>';
                
                // Add inline script for repair button
                add_action('admin_footer', function() {
                    ?>
                    <script>
                    jQuery(document).ready(function($) {
                        $('#gdpr-repair-tables').on('click', function(e) {
                            e.preventDefault();
                            
                            $(this).prop('disabled', true).text('<?php echo esc_js(__('Repairing...', 'wp-gdpr-framework')); ?>');
                            
                            $.ajax({
                                url: ajaxurl,
                                method: 'POST',
                                data: {
                                    action: 'gdpr_repair_tables',
                                    nonce: '<?php echo wp_create_nonce('gdpr_repair_tables'); ?>'
                                },
                                success: function(response) {
                                    if (response.success) {
                                        location.reload();
                                    } else {
                                        alert(response.data.message || '<?php echo esc_js(__('Repair failed', 'wp-gdpr-framework')); ?>');
                                        $('#gdpr-repair-tables').prop('disabled', false)
                                           .text('<?php echo esc_js(__('Attempt Repair', 'wp-gdpr-framework')); ?>');
                                    }
                                },
                                error: function() {
                                    alert('<?php echo esc_js(__('Repair request failed', 'wp-gdpr-framework')); ?>');
                                    $('#gdpr-repair-tables').prop('disabled', false)
                                       .text('<?php echo esc_js(__('Attempt Repair', 'wp-gdpr-framework')); ?>');
                                }
                            });
                        });
                    });
                    </script>
                    <?php
                });
            });
            
            // Add AJAX handler for table repair
            add_action('wp_ajax_gdpr_repair_tables', function() {
                // Verify nonce
                if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'gdpr_repair_tables')) {
                    wp_send_json_error(['message' => __('Security check failed', 'wp-gdpr-framework')]);
                    return;
                }
                
                // Verify user has necessary permissions
                if (!current_user_can('manage_options')) {
                    wp_send_json_error(['message' => __('You do not have permission to perform this action', 'wp-gdpr-framework')]);
                    return;
                }
                
                try {
                    $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
                    $framework->getDatabase()->createTables();
                    
                    // Verify tables were created successfully
                    if ($framework->verifyTables()) {
                        wp_send_json_success(['message' => __('Tables repaired successfully', 'wp-gdpr-framework')]);
                    } else {
                        wp_send_json_error(['message' => __('Failed to repair tables', 'wp-gdpr-framework')]);
                    }
                } catch (\Exception $e) {
                    wp_send_json_error(['message' => $e->getMessage()]);
                }
            });
            
            return;
        }
        
    } catch (\Exception $e) {
        error_log('GDPR Framework Init Error: ' . $e->getMessage());
        add_action('admin_notices', function() use ($e) {
            echo '<div class="notice notice-error"><p>' . 
                 esc_html__('GDPR Framework initialization failed: ', 'wp-gdpr-framework') . 
                 esc_html($e->getMessage()) . '</p></div>';
        });
    }
}

// Add error handler
function gdpr_framework_error_handler($errno, $errstr, $errfile, $errline) {
    // Only log errors we care about
    if (!(error_reporting() & $errno)) {
        return false;
    }
    
    // Create a more informative error message
    $error_type = '';
    switch ($errno) {
        case E_ERROR:
            $error_type = 'Fatal Error';
            break;
        case E_WARNING:
            $error_type = 'Warning';
            break;
        case E_PARSE:
            $error_type = 'Parse Error';
            break;
        default:
            $error_type = 'Unknown Error';
    }
    
    // Get the relative path for cleaner logs
    $relative_file = str_replace(GDPR_FRAMEWORK_PATH, '', $errfile);
    
    // Log the error with better formatting
    error_log("GDPR Framework {$error_type}: {$errstr} in {$relative_file} on line {$errline}");
    
    // Don't execute PHP's internal error handler
    return true;
}

// Only set our error handler for specific error types
set_error_handler('gdpr_framework_error_handler', E_ERROR | E_WARNING | E_PARSE);

add_action('plugins_loaded', 'gdpr_framework_init');
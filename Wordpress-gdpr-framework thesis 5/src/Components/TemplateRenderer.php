<?php
namespace GDPRFramework\Components;

class TemplateRenderer {
    private $settings;

    public function __construct($settings) {
        $this->settings = $settings;
    }

 /**
 * Render a template with provided data
 * 
 * @param string $template Template path relative to templates directory
 * @param array $data Data to pass to the template
 * @return string Rendered template content
 */
public function render($template, $data = []) {
    // Verify template file exists
    $template_file = GDPR_FRAMEWORK_PATH . 'templates/' . $template . '.php';
    
    if (!file_exists($template_file)) {
        error_log("GDPR Framework - Template not found: {$template}");
        return '<div class="notice notice-error"><p>' . 
               sprintf(__('Template %s not found.', 'wp-gdpr-framework'), esc_html($template)) . 
               '</p></div>';
    }

    // Ensure data is an array
    if (!is_array($data)) {
        $data = [];
    }
    
    // Add default variables to prevent undefined variable notices
    $default_variables = [
        'consent' => null,
        'portability' => null,
        'encryption' => null,
        'audit' => null,
        'stats' => [],
        'database_ok' => false,
        'cleanup_status' => [
            'next_run' => __('Not scheduled', 'wp-gdpr-framework'),
            'last_run' => __('Never', 'wp-gdpr-framework')
        ],
        'consent_types' => [],
        'settings' => null,
        'access_manager' => null,
        'user_id' => 0,
        'recent_exports' => [],
        'atts' => [],
        'result' => ['logs' => [], 'total' => 0, 'pages' => 0],
        'logs' => [],
        'total_pages' => 0,
        'current_page' => 1
    ];
    
    // Merge default variables with provided data (provided data takes precedence)
    $data = array_merge($default_variables, $data);
    
    // Sanitize data
    $data = $this->sanitizeTemplateData($data);
    
    // Make data available to template
    extract($data);

    // Start output buffering to catch errors
    ob_start();

    try {
        // Include template
        include $template_file;
        
        // Return the buffered content
        return ob_get_clean();
    } catch (\Exception $e) {
        // Clean buffer
        ob_end_clean();
        
        // Log error
        error_log("GDPR Framework - Template rendering error for {$template}: " . $e->getMessage());
        
        // Return error message
        return '<div class="notice notice-error"><p>' . 
               sprintf(__('Error rendering template %s: %s', 'wp-gdpr-framework'), 
                       esc_html($template), 
                       esc_html($e->getMessage())) . 
               '</p></div>';
    }
}

    /**
     * Sanitize data before passing to templates
     * 
     * @param array $data Raw data
     * @return array Sanitized data
     */
    private function sanitizeTemplateData($data) {
        // Ensure we have an array
        if (!is_array($data)) {
            return [];
        }
        
        // Return as-is, WordPress escaping functions should be used in templates
        return $data;
    }

    /**
     * Render the privacy dashboard
     * 
     * @param array $atts Shortcode attributes
     * @return string Rendered content
     */
    public function renderPrivacyDashboard($atts = []) {
        if (!is_user_logged_in()) {
            return sprintf(
                '<p>%s</p>',
                __('Please log in to access your privacy dashboard.', 'wp-gdpr-framework')
            );
        }
    
        $user_id = get_current_user_id();
        
        try {
            // Get a GDPR Framework instance to access components
            $framework = \GDPRFramework\Core\GDPRFramework::getInstance();
            
            // Get recent exports if portability component exists
            $recent_exports = [];
            if (isset($framework->components['portability'])) {
                $recent_exports = $framework->components['portability']->getRecentExports($user_id);
            }
            
            // Get consent types
            $consent_types = get_option('gdpr_consent_types', []);
            
            // Render the template
            return $this->render('public/privacy-dashboard', [
                'user_id' => $user_id,
                'recent_exports' => $recent_exports,
                'consent_types' => $consent_types
            ]);
        } catch (\Exception $e) {
            error_log('GDPR Framework - Privacy Dashboard Error: ' . $e->getMessage());
            return '<div class="gdpr-notice gdpr-error"><p>' . 
                   __('An error occurred while loading the privacy dashboard.', 'wp-gdpr-framework') . 
                   '</p></div>';
        }
    }
}
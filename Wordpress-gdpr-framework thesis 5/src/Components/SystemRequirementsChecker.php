<?php
namespace GDPRFramework\Components;

/**
 * System Requirements Checker
 * 
 * Checks if the hosting environment meets the requirements
 * specified in the Appendix A documentation
 */
class SystemRequirementsChecker {
    private $requirements = [];
    private $results = [];
    
    public function __construct() {
        $this->defineRequirements();
    }
    
    /**
     * Define system requirements as per Appendix A
     */
    private function defineRequirements() {
        $this->requirements = [
            'wordpress' => [
                'name' => 'WordPress Version',
                'min' => '5.8',
                'recommended' => 'latest',
                'current' => $this->getWordPressVersion(),
                'check' => 'checkWordPressVersion',
                'docs_url' => 'https://wordpress.org/download/'
            ],
            'php' => [
                'name' => 'PHP Version',
                'min' => '7.4',
                'recommended' => '8.0',
                'current' => PHP_VERSION,
                'check' => 'checkPHPVersion',
                'docs_url' => 'https://php.net/'
            ],
            'mysql' => [
                'name' => 'MySQL/MariaDB Version',
                'min' => '5.7',
                'recommended' => '10.5',
                'current' => $this->getDatabaseVersion(),
                'check' => 'checkDatabaseVersion',
                'docs_url' => 'https://mariadb.org/'
            ],
            'ssl' => [
                'name' => 'SSL/TLS Version',
                'min' => '1.2',
                'recommended' => '1.3',
                'current' => $this->getTLSVersion(),
                'check' => 'checkTLSVersion',
                'docs_url' => 'https://letsencrypt.org/'
            ],
            'openssl' => [
                'name' => 'OpenSSL Extension',
                'min' => '1.1.1',
                'recommended' => '1.1.1+',
                'current' => $this->getOpenSSLVersion(),
                'check' => 'checkOpenSSLVersion',
                'docs_url' => 'https://www.openssl.org/'
            ],
            'caching' => [
                'name' => 'Object Caching',
                'min' => 'WP Default',
                'recommended' => 'Redis/Memcached',
                'current' => $this->detectCaching(),
                'check' => 'checkCaching',
                'docs_url' => 'https://developer.wordpress.org/reference/classes/wp_object_cache/'
            ]
        ];
    }
    
    /**
     * Run all system checks
     * 
     * @return array Check results
     */
    public function checkAll() {
        $this->results = [];
        
        foreach ($this->requirements as $key => $requirement) {
            $check_method = $requirement['check'];
            $this->results[$key] = $this->$check_method();
        }
        
        return $this->results;
    }
    
    /**
     * Check if WordPress version meets requirements
     */
    private function checkWordPressVersion() {
        $current = $this->getWordPressVersion();
        $min = $this->requirements['wordpress']['min'];
        
        $meets_min = version_compare($current, $min, '>=');
        
        return [
            'name' => $this->requirements['wordpress']['name'],
            'min' => $min,
            'recommended' => $this->requirements['wordpress']['recommended'],
            'current' => $current,
            'status' => $meets_min ? 'ok' : 'error',
            'message' => $meets_min 
                ? sprintf(__('WordPress %s meets minimum requirement of %s', 'wp-gdpr-framework'), $current, $min)
                : sprintf(__('WordPress %s does not meet minimum requirement of %s', 'wp-gdpr-framework'), $current, $min)
        ];
    }
    
    /**
     * Check if PHP version meets requirements
     */
    private function checkPHPVersion() {
        $current = PHP_VERSION;
        $min = $this->requirements['php']['min'];
        $recommended = $this->requirements['php']['recommended'];
        
        $meets_min = version_compare($current, $min, '>=');
        $meets_recommended = version_compare($current, $recommended, '>=');
        
        $status = 'error';
        if ($meets_min && $meets_recommended) {
            $status = 'ok';
        } elseif ($meets_min) {
            $status = 'warning';
        }
        
        return [
            'name' => $this->requirements['php']['name'],
            'min' => $min,
            'recommended' => $recommended,
            'current' => $current,
            'status' => $status,
            'message' => $this->getPHPVersionMessage($current, $min, $recommended, $status)
        ];
    }
    
    /**
     * Get appropriate message for PHP version check
     */
    private function getPHPVersionMessage($current, $min, $recommended, $status) {
        switch ($status) {
            case 'ok':
                return sprintf(
                    __('PHP %s meets recommended version %s', 'wp-gdpr-framework'),
                    $current,
                    $recommended
                );
                
            case 'warning':
                return sprintf(
                    __('PHP %s meets minimum version %s but is below recommended %s', 'wp-gdpr-framework'),
                    $current,
                    $min,
                    $recommended
                );
                
            default:
                return sprintf(
                    __('PHP %s does not meet minimum requirement of %s', 'wp-gdpr-framework'),
                    $current,
                    $min
                );
        }
    }
    
    /**
     * Check if database version meets requirements
     */
    private function checkDatabaseVersion() {
        $current = $this->getDatabaseVersion();
        $min = $this->requirements['mysql']['min'];
        $recommended = $this->requirements['mysql']['recommended'];
        
        $is_mariadb = strpos(strtolower($current), 'mariadb') !== false;
        
        // Extract version number
        preg_match('/[\d\.]+/', $current, $matches);
        $version = $matches[0] ?? '0.0';
        
        $min_to_check = $is_mariadb ? '10.3' : $min;
        $meets_min = version_compare($version, $min_to_check, '>=');
        
        $rec_to_check = $is_mariadb ? $recommended : '8.0';
        $meets_recommended = version_compare($version, $rec_to_check, '>=');
        
        $status = 'error';
        if ($meets_min && $meets_recommended) {
            $status = 'ok';
        } elseif ($meets_min) {
            $status = 'warning';
        }
        
        return [
            'name' => $this->requirements['mysql']['name'],
            'min' => $is_mariadb ? '10.3+' : "$min+",
            'recommended' => $is_mariadb ? "$recommended+" : '8.0+',
            'current' => $current,
            'status' => $status,
            'message' => $this->getDatabaseVersionMessage($current, $min_to_check, $rec_to_check, $status, $is_mariadb)
        ];
    }
    
    /**
     * Get appropriate message for database version check
     */
    private function getDatabaseVersionMessage($current, $min, $recommended, $status, $is_mariadb) {
        $db_type = $is_mariadb ? 'MariaDB' : 'MySQL';
        
        switch ($status) {
            case 'ok':
                return sprintf(
                    __('%s %s meets recommended version %s', 'wp-gdpr-framework'),
                    $db_type,
                    $current,
                    $recommended
                );
                
            case 'warning':
                return sprintf(
                    __('%s %s meets minimum version %s but is below recommended %s', 'wp-gdpr-framework'),
                    $db_type,
                    $current,
                    $min,
                    $recommended
                );
                
            default:
                return sprintf(
                    __('%s %s does not meet minimum requirement of %s', 'wp-gdpr-framework'),
                    $db_type,
                    $current,
                    $min
                );
        }
    }
    
    /**
     * Check if OpenSSL version meets requirements
     */
    private function checkOpenSSLVersion() {
        $current = $this->getOpenSSLVersion();
        $min = $this->requirements['openssl']['min'];
        
        if (!extension_loaded('openssl')) {
            return [
                'name' => $this->requirements['openssl']['name'],
                'min' => $min,
                'recommended' => $this->requirements['openssl']['recommended'],
                'current' => 'Not Available',
                'status' => 'error',
                'message' => __('OpenSSL extension is not available. GDPR encryption features will not work.', 'wp-gdpr-framework')
            ];
        }
        
        preg_match('/[\d\.]+/', $current, $matches);
        $version = $matches[0] ?? '0.0';
        
        $meets_min = version_compare($version, $min, '>=');
        
        return [
            'name' => $this->requirements['openssl']['name'],
            'min' => $min,
            'recommended' => $this->requirements['openssl']['recommended'],
            'current' => $current,
            'status' => $meets_min ? 'ok' : 'warning',
            'message' => $meets_min 
                ? sprintf(__('OpenSSL %s meets minimum requirement of %s', 'wp-gdpr-framework'), $current, $min)
                : sprintf(__('OpenSSL %s is below recommended version %s', 'wp-gdpr-framework'), $current, $min)
        ];
    }
    
    /**
     * Check if TLS version meets requirements
     */
    private function checkTLSVersion() {
        $current = $this->getTLSVersion();
        $min = $this->requirements['ssl']['min'];
        $recommended = $this->requirements['ssl']['recommended'];
        
        if ($current === 'Unknown') {
            return [
                'name' => $this->requirements['ssl']['name'],
                'min' => $min,
                'recommended' => $recommended,
                'current' => $current,
                'status' => 'warning',
                'message' => __('TLS version could not be determined. Please ensure you\'re using TLS 1.2+ for secure connections.', 'wp-gdpr-framework')
            ];
        }
        
        $meets_min = version_compare($current, $min, '>=');
        $meets_recommended = version_compare($current, $recommended, '>=');
        
        $status = 'error';
        if ($meets_min && $meets_recommended) {
            $status = 'ok';
        } elseif ($meets_min) {
            $status = 'warning';
        }
        
        return [
            'name' => $this->requirements['ssl']['name'],
            'min' => $min,
            'recommended' => $recommended,
            'current' => $current,
            'status' => $status,
            'message' => $this->getTLSVersionMessage($current, $min, $recommended, $status)
        ];
    }
    
    /**
     * Get appropriate message for TLS version check
     */
    private function getTLSVersionMessage($current, $min, $recommended, $status) {
        switch ($status) {
            case 'ok':
                return sprintf(
                    __('TLS %s meets recommended version %s', 'wp-gdpr-framework'),
                    $current,
                    $recommended
                );
                
            case 'warning':
                return sprintf(
                    __('TLS %s meets minimum version %s but is below recommended %s', 'wp-gdpr-framework'),
                    $current,
                    $min,
                    $recommended
                );
                
            default:
                return sprintf(
                    __('TLS %s does not meet minimum requirement of %s', 'wp-gdpr-framework'),
                    $current,
                    $min
                );
        }
    }
    
    /**
     * Check if caching system meets requirements
     */
    private function checkCaching() {
        $current = $this->detectCaching();
        $min = $this->requirements['caching']['min'];
        $recommended = $this->requirements['caching']['recommended'];
        
        $meets_recommended = in_array($current, ['Redis', 'Memcached']);
        
        return [
            'name' => $this->requirements['caching']['name'],
            'min' => $min,
            'recommended' => $recommended,
            'current' => $current,
            'status' => $meets_recommended ? 'ok' : 'warning',
            'message' => $meets_recommended 
                ? sprintf(__('%s caching is enabled (recommended)', 'wp-gdpr-framework'), $current)
                : __('Using WordPress default object cache. Consider using Redis or Memcached for better performance.', 'wp-gdpr-framework')
        ];
    }
    
    /**
     * Get WordPress version
     */
    private function getWordPressVersion() {
        global $wp_version;
        return $wp_version;
    }
    
    /**
     * Get database version
     */
    private function getDatabaseVersion() {
        global $wpdb;
        return $wpdb->db_version();
    }
    
    /**
     * Get OpenSSL version
     */
    private function getOpenSSLVersion() {
        if (!extension_loaded('openssl')) {
            return 'Not Available';
        }
        
        return OPENSSL_VERSION_TEXT;
    }
    
    /**
     * Try to detect TLS version
     */
    private function getTLSVersion() {
        // This is an approximation - it's difficult to determine the exact TLS version from PHP
        if (!extension_loaded('openssl')) {
            return 'Unknown';
        }
        
        $constants = [
            'CURL_SSLVERSION_TLSv1_3' => '1.3',
            'CURL_SSLVERSION_TLSv1_2' => '1.2',
            'CURL_SSLVERSION_TLSv1_1' => '1.1',
            'CURL_SSLVERSION_TLSv1_0' => '1.0'
        ];
        
        // Use the highest available version as the current version
        foreach ($constants as $constant => $version) {
            if (defined($constant)) {
                return $version;
            }
        }
        
        // If we can't determine, check if HTTPS is enabled
        if (is_ssl()) {
            return '1.2'; // Assume at least TLS 1.2 for SSL
        }
        
        return 'Unknown';
    }
    
    /**
     * Detect caching system in use
     */
    private function detectCaching() {
        // Check for Redis
        if (class_exists('Redis') && function_exists('wp_cache_add_redis_servers')) {
            return 'Redis';
        }
        
        // Check for Memcached
        if (class_exists('Memcached') && function_exists('wp_cache_add_memcached_servers')) {
            return 'Memcached';
        }
        
        // Check for APCu
        if (function_exists('apcu_add')) {
            return 'APCu';
        }
        
        // Check if an object cache drop-in is being used
        if (file_exists(WP_CONTENT_DIR . '/object-cache.php')) {
            return 'Custom';
        }
        
        return 'WP Default';
    }
    
    /**
     * Get a summary of all requirements
     */
    public function getSummary() {
        if (empty($this->results)) {
            $this->checkAll();
        }
        
        $counts = [
            'ok' => 0,
            'warning' => 0,
            'error' => 0
        ];
        
        foreach ($this->results as $result) {
            $counts[$result['status']]++;
        }
        
        return [
            'total' => count($this->results),
            'pass' => $counts['ok'],
            'warning' => $counts['warning'],
            'error' => $counts['error'],
            'success_rate' => round(($counts['ok'] / count($this->results)) * 100)
        ];
    }
}
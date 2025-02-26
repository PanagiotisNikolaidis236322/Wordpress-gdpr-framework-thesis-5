<?php
namespace GDPRFramework\Components;

/**
 * GDPR Framework Caching Manager
 * 
 * Provides object caching functionality as per Appendix A specifications
 */
class CachingManager {
    private $enabled = false;
    private $cache_type = 'default'; // default, redis, memcached
    private $settings;
    private $cache_group = 'gdpr_framework';
    private $debug = false;

    public function __construct($settings) {
        $this->settings = $settings;
        $this->debug = defined('WP_DEBUG') && WP_DEBUG;
        
        // Check if Redis or Memcached is available
        $this->detectCachingSystem();
        
        // Initialize hooks
        add_action('admin_init', [$this, 'registerSettings']);
    }
    
    /**
     * Register caching settings
     */
    public function registerSettings() {
        register_setting('gdpr_framework_settings', 'gdpr_enable_object_caching', [
            'type' => 'boolean',
            'default' => 1,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_cache_expiration', [
            'type' => 'integer',
            'default' => 3600, // 1 hour default
            'sanitize_callback' => [$this, 'sanitizeCacheExpiration']
        ]);
        
        // Register settings fields
        add_settings_section(
            'gdpr_caching_section',
            __('Performance Optimization', 'wp-gdpr-framework'),
            [$this, 'renderCachingSection'],
            'gdpr_framework_settings'
        );
        
        add_settings_field(
            'gdpr_enable_object_caching',
            __('Enable Object Caching', 'wp-gdpr-framework'),
            [$this, 'renderObjectCachingField'],
            'gdpr_framework_settings',
            'gdpr_caching_section'
        );
        
        add_settings_field(
            'gdpr_cache_expiration',
            __('Cache Expiration', 'wp-gdpr-framework'),
            [$this, 'renderCacheExpirationField'],
            'gdpr_framework_settings',
            'gdpr_caching_section'
        );
    }
    
    /**
     * Render caching section description
     */
    public function renderCachingSection() {
        echo '<p>' . esc_html__('Configure caching settings for optimal performance.', 'wp-gdpr-framework') . '</p>';
        
        // Display current caching system
        echo '<p><strong>' . esc_html__('Detected Caching System:', 'wp-gdpr-framework') . '</strong> ';
        
        switch ($this->cache_type) {
            case 'redis':
                echo '<span class="dashicons dashicons-yes"></span> ' . 
                     esc_html__('Redis (Recommended)', 'wp-gdpr-framework');
                break;
                
            case 'memcached':
                echo '<span class="dashicons dashicons-yes"></span> ' . 
                     esc_html__('Memcached (Recommended)', 'wp-gdpr-framework');
                break;
                
            default:
                echo '<span class="dashicons dashicons-warning"></span> ' . 
                     esc_html__('WordPress Default', 'wp-gdpr-framework') . 
                     ' <small>(' . esc_html__('Redis or Memcached recommended for production use', 'wp-gdpr-framework') . ')</small>';
        }
        
        echo '</p>';
    }
    
    /**
     * Render object caching field
     */
    public function renderObjectCachingField() {
        $enabled = get_option('gdpr_enable_object_caching', 1);
        
        echo '<input type="checkbox" id="gdpr_enable_object_caching" name="gdpr_enable_object_caching" value="1" ' . 
             checked($enabled, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Enable object caching for GDPR logs, consent data, and other frequently accessed data.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render cache expiration field
     */
    public function renderCacheExpirationField() {
        $expiration = get_option('gdpr_cache_expiration', 3600);
        
        echo '<input type="number" id="gdpr_cache_expiration" name="gdpr_cache_expiration" value="' . 
             esc_attr($expiration) . '" min="60" max="86400" step="60" class="small-text"> ' . 
             esc_html__('seconds', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('How long to keep items in cache (60-86400 seconds).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Sanitize cache expiration setting
     */
    public function sanitizeCacheExpiration($value) {
        $value = absint($value);
        
        if ($value < 60) {
            return 60; // Minimum 1 minute
        }
        
        if ($value > 86400) {
            return 86400; // Maximum 1 day
        }
        
        return $value;
    }
    
    /**
     * Detect available caching system
     */
    private function detectCachingSystem() {
        // Check if caching is enabled in settings
        $this->enabled = get_option('gdpr_enable_object_caching', 1);
        
        if (!$this->enabled) {
            return;
        }
        
        // Check for Redis
        if (class_exists('Redis') && function_exists('wp_cache_add_redis_servers')) {
            $this->cache_type = 'redis';
            if ($this->debug) {
                error_log('GDPR Framework - Redis detected for caching');
            }
            return;
        }
        
        // Check for Memcached
        if (class_exists('Memcached') && function_exists('wp_cache_add_memcached_servers')) {
            $this->cache_type = 'memcached';
            if ($this->debug) {
                error_log('GDPR Framework - Memcached detected for caching');
            }
            return;
        }
        
        // Using WordPress default object cache
        if ($this->debug) {
            error_log('GDPR Framework - Using WordPress default object cache (non-persistent)');
        }
    }
    
    /**
     * Get an item from cache
     *
     * @param string $key Cache key
     * @param mixed $default Default value if key doesn't exist
     * @return mixed Cached value or default
     */
    public function get($key, $default = null) {
        if (!$this->enabled) {
            return $default;
        }
        
        $full_key = $this->prefixKey($key);
        $value = wp_cache_get($full_key, $this->cache_group);
        
        return $value !== false ? $value : $default;
    }
    
    /**
     * Store an item in cache
     *
     * @param string $key Cache key
     * @param mixed $value Value to store
     * @param int $expiration Expiration time in seconds (0 = no expiration)
     * @return bool Success status
     */
    public function set($key, $value, $expiration = null) {
        if (!$this->enabled) {
            return false;
        }
        
        // Use default expiration if not specified
        if ($expiration === null) {
            $expiration = get_option('gdpr_cache_expiration', 3600);
        }
        
        $full_key = $this->prefixKey($key);
        return wp_cache_set($full_key, $value, $this->cache_group, $expiration);
    }
    
    /**
     * Delete an item from cache
     *
     * @param string $key Cache key
     * @return bool Success status
     */
    public function delete($key) {
        if (!$this->enabled) {
            return false;
        }
        
        $full_key = $this->prefixKey($key);
        return wp_cache_delete($full_key, $this->cache_group);
    }
    
    /**
     * Flush all cache items
     *
     * @return bool Success status
     */
    public function flush() {
        if (!$this->enabled) {
            return false;
        }
        
        return wp_cache_flush();
    }
    
    /**
     * Generate a consistent cache key
     *
     * @param string $key Original key
     * @return string Prefixed key
     */
    private function prefixKey($key) {
        // Add a version prefix to invalidate cache when plugin is updated
        return 'gdpr_' . GDPR_FRAMEWORK_VERSION . '_' . $key;
    }
    
    /**
     * Get information about caching system
     *
     * @return array Caching system information
     */
    public function getCacheInfo() {
        return [
            'enabled' => $this->enabled,
            'type' => $this->cache_type,
            'persistent' => ($this->cache_type !== 'default'),
            'expiration' => get_option('gdpr_cache_expiration', 3600)
        ];
    }
}
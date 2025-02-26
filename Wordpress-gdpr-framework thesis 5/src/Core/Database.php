<?php
namespace GDPRFramework\Core;

class Database {
    protected $wpdb;
    protected $tables;
    protected $indexes;
    public $insert_id;

    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
        $this->defineTables();
        $this->defineIndexes();
    }

    private function defineTables() {
        $charset_collate = $this->wpdb->get_charset_collate();
        $prefix = $this->wpdb->prefix . 'gdpr_';
        
        $this->tables = [
            'user_consents' => "CREATE TABLE IF NOT EXISTS {$prefix}user_consents (
                    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                    user_id bigint(20) unsigned NOT NULL,
                    consent_type varchar(50) NOT NULL,
                    status tinyint(1) NOT NULL DEFAULT 0,
                    ip_address varchar(45),
                    user_agent text,
                    timestamp datetime DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    KEY user_id (user_id),
                    KEY consent_type (consent_type),
                    KEY user_consent_status (user_id, consent_type, status)
                ) $charset_collate",
                
            'user_data' => "CREATE TABLE IF NOT EXISTS {$prefix}user_data (
                    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                    user_id bigint(20) unsigned NOT NULL,
                    data_type varchar(50) NOT NULL,
                    encrypted_data text NOT NULL,
                    created_at datetime DEFAULT CURRENT_TIMESTAMP,
                    updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    KEY user_id (user_id),
                    KEY data_type (data_type)
                ) $charset_collate",
                
            'audit_log' => "CREATE TABLE IF NOT EXISTS {$prefix}audit_log (
                    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                    user_id bigint(20) unsigned NULL,
                    action varchar(100) NOT NULL,
                    details text,
                    severity enum('low', 'medium', 'high') DEFAULT 'low',
                    ip_address varchar(45),
                    user_agent text,
                    timestamp datetime DEFAULT CURRENT_TIMESTAMP,
                    integrity_hash varchar(128) DEFAULT NULL,
                    PRIMARY KEY (id),
                    KEY user_id (user_id),
                    KEY action (action),
                    KEY severity (severity),
                    KEY timestamp (timestamp)
                ) $charset_collate",
                
            'data_requests' => "CREATE TABLE IF NOT EXISTS {$prefix}data_requests (
                    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                    user_id bigint(20) unsigned NOT NULL,
                    request_type enum('export', 'erasure') NOT NULL,
                    status enum('pending', 'processing', 'completed', 'failed', 'expired') NOT NULL DEFAULT 'pending',
                    created_at datetime DEFAULT CURRENT_TIMESTAMP,
                    completed_at datetime NULL,
                    details text,
                    PRIMARY KEY (id),
                    KEY user_id (user_id),
                    KEY request_type_status (request_type, status)
                ) $charset_collate",

            'login_log' => "CREATE TABLE IF NOT EXISTS {$prefix}login_log (
                    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                    user_id bigint(20) unsigned NULL,
                    success tinyint(1) NOT NULL DEFAULT 0,
                    ip_address varchar(45) NOT NULL,
                    user_agent text,
                    timestamp datetime DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    KEY user_id (user_id),
                    KEY ip_address (ip_address),
                    KEY ip_success (ip_address, success)
                ) $charset_collate"
        ];
    }
    
    /**
     * Define additional indexes for performance optimization
     */
    private function defineIndexes() {
        $prefix = $this->wpdb->prefix . 'gdpr_';
        
        // Define additional indexes that may need to be added separately
        // Format: 'table_name' => [['index_name', 'column1,column2']]
        $this->indexes = [
            'user_consents' => [
                ['consent_timestamp', 'consent_type,timestamp'],
                ['user_timestamp', 'user_id,timestamp']
            ],
            'audit_log' => [
                ['user_timestamp', 'user_id,timestamp'],
                ['severity_timestamp', 'severity,timestamp']
            ],
            'data_requests' => [
                ['status_created', 'status,created_at'],
                ['user_created', 'user_id,created_at']
            ],
            'login_log' => [
                ['timestamp_index', 'timestamp'],
                ['ip_timestamp', 'ip_address,timestamp']
            ]
        ];
    }

    public function createTables() {
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        
        foreach ($this->tables as $sql) {
            dbDelta($sql);
        }
        
        // Create additional indexes
        $this->createIndexes();
    }
    
    /**
     * Create additional indexes for performance optimization
     */
    public function createIndexes() {
        foreach ($this->indexes as $table => $indexes) {
            $table_name = $this->wpdb->prefix . 'gdpr_' . $table;
            
            // Check if table exists
            if (!$this->tableExists($table_name)) {
                continue;
            }
            
            foreach ($indexes as $index_info) {
                list($index_name, $columns) = $index_info;
                
                // Check if index already exists
                $index_exists = $this->wpdb->get_results(
                    $this->wpdb->prepare(
                        "SHOW INDEX FROM {$table_name} WHERE Key_name = %s",
                        $index_name
                    )
                );
                
                if (empty($index_exists)) {
                    // Create the index
                    try {
                        $this->wpdb->query(
                            "ALTER TABLE {$table_name} ADD INDEX {$index_name} ({$columns})"
                        );
                        
                        if ($this->wpdb->last_error) {
                            error_log("GDPR Framework - Failed to create index {$index_name} on {$table_name}: " . $this->wpdb->last_error);
                        }
                    } catch (\Exception $e) {
                        error_log("GDPR Framework - Failed to create index {$index_name} on {$table_name}: " . $e->getMessage());
                    }
                }
            }
        }
    }

    public function insert($table_suffix, $data, $format = null) {
        $table_name = $this->wpdb->prefix . 'gdpr_' . $table_suffix;
        
        // Check if table exists before inserting
        if (!$this->tableExists($table_name)) {
            error_log('GDPR Framework - Table does not exist: ' . $table_name);
            return false;
        }
        
        $result = $this->wpdb->insert($table_name, $data, $format);
        
        if ($result === false) {
            error_log('GDPR Framework - Database Insert Error: ' . $this->wpdb->last_error);
            return false;
        }
        
        $this->insert_id = $this->wpdb->insert_id;
        return true;
    }
    
    public function update($table_suffix, $data, $where, $format = null, $where_format = null) {
        $table_name = $this->wpdb->prefix . 'gdpr_' . $table_suffix;
        
        // Check if table exists before updating
        if (!$this->tableExists($table_name)) {
            error_log('GDPR Framework - Table does not exist: ' . $table_name);
            return false;
        }
        
        return $this->wpdb->update($table_name, $data, $where, $format, $where_format);
    }
    
    public function delete($table_suffix, $where, $where_format = null) {
        $table_name = $this->wpdb->prefix . 'gdpr_' . $table_suffix;
        
        // Check if table exists before deleting
        if (!$this->tableExists($table_name)) {
            error_log('GDPR Framework - Table does not exist: ' . $table_name);
            return false;
        }
        
        return $this->wpdb->delete($table_name, $where, $where_format);
    }

    private function tableExists($table_name) {
        return $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $table_name
            )
        ) === $table_name;
    }

    public function get_var($query, $args = []) {
        if (!empty($args)) {
            return $this->wpdb->get_var($this->prepare($query, ...$args));
        }
        return $this->wpdb->get_var($query);
    }

    public function get_row($query, $args = [], $output = OBJECT) {
        if (is_array($query)) {
            return $this->wpdb->get_row($this->prepare($query[0], array_slice($query, 1)), $output);
        }
        return $this->wpdb->get_row($query, $output);
    }

    public function get_results($query, $output = OBJECT) {
        if (is_array($query)) {
            return $this->wpdb->get_results($this->prepare($query[0], array_slice($query, 1)), $output);
        }
        return $this->wpdb->get_results($query, $output);
    }

    public function prepare($query, ...$args) {
        return $this->wpdb->prepare($query, ...$args);
    }

    public function query($query, $args = []) {
        if (!empty($args)) {
            return $this->wpdb->get_results($this->prepare($query, $args));
        }
        return $this->wpdb->get_results($query);
    }

    public function get_prefix() {
        return $this->wpdb->prefix;
    }

    public function get_last_error() {
        return $this->wpdb->last_error;
    }

    public function beginTransaction() {
        $this->wpdb->query('START TRANSACTION');
    }

    public function commit() {
        $this->wpdb->query('COMMIT');
    }

    public function rollback() {
        $this->wpdb->query('ROLLBACK');
    }

    public function verifyTables() {
        $errors = [];
        $prefix = $this->wpdb->prefix . 'gdpr_';
        
        foreach (array_keys($this->tables) as $table) {
            $table_name = $prefix . $table;
            $table_exists = $this->wpdb->get_var(
                $this->wpdb->prepare(
                    "SHOW TABLES LIKE %s",
                    $table_name
                )
            );
            
            if (!$table_exists) {
                $errors[] = "Table {$table_name} missing";
                error_log("GDPR Framework: Missing table {$table_name}");
            }
        }
        
        return empty($errors);
    }
    
    /**
     * Optimize database tables for better performance
     * Especially important for large datasets
     */
    public function optimizeTables() {
        $prefix = $this->wpdb->prefix . 'gdpr_';
        $optimized = [];
        
        foreach (array_keys($this->tables) as $table) {
            $table_name = $prefix . $table;
            
            if ($this->tableExists($table_name)) {
                $result = $this->wpdb->query("OPTIMIZE TABLE {$table_name}");
                
                if ($result) {
                    $optimized[] = $table_name;
                } else {
                    error_log("GDPR Framework: Failed to optimize table {$table_name}");
                }
            }
        }
        
        return $optimized;
    }
    
    /**
     * Get database status information including table sizes
     * Useful for performance monitoring
     */
    public function getTableStatus() {
        $prefix = $this->wpdb->prefix . 'gdpr_';
        $tables = [];
        
        foreach (array_keys($this->tables) as $table) {
            $table_name = $prefix . $table;
            
            if ($this->tableExists($table_name)) {
                $result = $this->wpdb->get_row("SHOW TABLE STATUS LIKE '{$table_name}'");
                
                if ($result) {
                    // Convert to human-readable size
                    $data_size = $this->formatBytes($result->Data_length);
                    $index_size = $this->formatBytes($result->Index_length);
                    
                    $tables[$table] = [
                        'name' => $table_name,
                        'rows' => $result->Rows,
                        'data_size' => $data_size,
                        'index_size' => $index_size,
                        'total_size' => $this->formatBytes($result->Data_length + $result->Index_length),
                        'engine' => $result->Engine,
                        'last_update' => $result->Update_time
                    ];
                }
            }
        }
        
        return $tables;
    }
    
    /**
     * Format bytes to human-readable format
     */
    private function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= (1 << (10 * $pow));
        
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
}
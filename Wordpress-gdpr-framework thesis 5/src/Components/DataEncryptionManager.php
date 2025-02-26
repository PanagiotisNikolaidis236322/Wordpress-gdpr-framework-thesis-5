<?php
namespace GDPRFramework\Components;

class DataEncryptionManager {
    private $db;
    private $settings;
    private $cipher = 'aes-256-cbc'; // AES-256 encryption as required in Appendix A
    private $key;
    private $min_openssl_version = '1.1.1'; // Minimum required OpenSSL version
    private $active_key_id = null;

    public function __construct($database, $settings) {
        $this->db = $database;
        $this->settings = $settings;
        
        // Check OpenSSL availability and version
        if (!extension_loaded('openssl')) {
            throw new \Exception('OpenSSL extension not available. Encryption functionality will not work.');
        } else {
            $this->verifyOpenSSLVersion();
        }
        
        $this->initializeKey();
        
        // Add AJAX handler
        add_action('wp_ajax_gdpr_rotate_key', [$this, 'handleKeyRotation']);
        
        // Add scheduled key rotation if enabled
        $this->setupScheduledKeyRotation();
    }
    
    /**
     * Verify OpenSSL version meets requirements
     */
    private function verifyOpenSSLVersion() {
        $openssl_version = OPENSSL_VERSION_TEXT;
        preg_match('/OpenSSL\s+([\d\.]+)/', $openssl_version, $matches);
        
        if (empty($matches[1]) || version_compare($matches[1], $this->min_openssl_version, '<')) {
            error_log('GDPR Framework - Warning: OpenSSL version ' . $openssl_version . 
                     ' is below recommended version ' . $this->min_openssl_version . 
                     '. Please upgrade for better security.');
        }
    }
    
    /**
     * Set up scheduled key rotation if enabled
     */
    private function setupScheduledKeyRotation() {
        $rotation_days = get_option('gdpr_auto_key_rotation', 0);
        
        // Clear existing scheduled event
        wp_clear_scheduled_hook('gdpr_scheduled_key_rotation');
        
        // If enabled, schedule new event
        if ($rotation_days > 0) {
            if (!wp_next_scheduled('gdpr_scheduled_key_rotation')) {
                wp_schedule_event(time(), 'daily', 'gdpr_scheduled_key_rotation');
            }
            
            // Add handler for scheduled key rotation
            add_action('gdpr_scheduled_key_rotation', [$this, 'checkAndRotateKey']);
        }
    }
    
    /**
     * Check if key rotation is due and perform if needed
     */
    public function checkAndRotateKey() {
        $rotation_days = get_option('gdpr_auto_key_rotation', 0);
        if ($rotation_days <= 0) {
            return false;
        }
        
        $last_rotation = get_option('gdpr_last_key_rotation', 0);
        $days_since_rotation = floor((time() - $last_rotation) / DAY_IN_SECONDS);
        
        if ($days_since_rotation >= $rotation_days) {
            try {
                $this->rotateKey();
                // Log successful automatic key rotation
                do_action('gdpr_key_rotated', 0, 'automatic');
                return true;
            } catch (\Exception $e) {
                error_log('GDPR Framework - Automatic key rotation failed: ' . $e->getMessage());
                // Log failed key rotation
                do_action('gdpr_key_rotation_failed', 0, $e->getMessage());
                return false;
            }
        }
        
        return false;
    }

    public function handleKeyRotation() {
        check_ajax_referer('gdpr_security_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You do not have permission to perform this action.', 'wp-gdpr-framework')]);
            return;
        }

        try {
            $this->rotateKey();
            update_option('gdpr_last_key_rotation', time());
            
            // Log successful key rotation
            do_action('gdpr_key_rotated', get_current_user_id(), 'manual');
            
            wp_send_json_success(['message' => __('Encryption key rotated successfully.', 'wp-gdpr-framework')]);
        } catch (\Exception $e) {
            // Log failed key rotation
            do_action('gdpr_key_rotation_failed', get_current_user_id(), $e->getMessage());
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Initialize or retrieve encryption key
     */
    private function initializeKey() {
        $key_data = get_option('gdpr_encryption_keys');
        
        if (!$key_data || empty($key_data['keys'])) {
            // Initialize with a new key
            $new_key = $this->generateKey();
            $key_id = uniqid('key_');
            
            $key_data = [
                'active_key_id' => $key_id,
                'keys' => [
                    $key_id => [
                        'key' => $new_key,
                        'created' => time()
                    ]
                ]
            ];
            
            update_option('gdpr_encryption_keys', $key_data);
            update_option('gdpr_last_key_rotation', time());
        }
        
        $this->active_key_id = $key_data['active_key_id'];
        $this->key = base64_decode($key_data['keys'][$this->active_key_id]['key']);
    }

    /**
     * Generate new encryption key with cryptographically secure randomness
     */
    private function generateKey() {
        // First try to use the most secure random source available
        if (function_exists('random_bytes')) {
            // PHP 7+ secure random bytes
            return base64_encode(random_bytes(32));
        } else if (function_exists('openssl_random_pseudo_bytes')) {
            // OpenSSL random bytes with cryptographic strength verification
            $bytes = openssl_random_pseudo_bytes(32, $strong);
            if ($strong) {
                return base64_encode($bytes);
            }
        }
        
        // If we got here, neither method worked - throw an exception
        throw new \Exception('Cannot generate cryptographically secure random key');
    }

    /**
     * Encrypt data using AES-256-CBC with proper IV handling
     */
    public function encrypt($data) {
        if (empty($data)) {
            return '';
        }

        if (!extension_loaded('openssl')) {
            throw new \Exception('Cannot encrypt data: OpenSSL extension not available');
        }

        try {
            // Generate cryptographically secure random IV
            $iv_length = openssl_cipher_iv_length($this->cipher);
            $iv = openssl_random_pseudo_bytes($iv_length, $secure);
            
            if (!$secure) {
                throw new \Exception('Failed to generate secure IV');
            }

            // Prepare data for encryption (serialize arrays)
            $data_to_encrypt = is_array($data) ? serialize($data) : $data;

            // Encrypt the data with the active key
            $encrypted = openssl_encrypt(
                $data_to_encrypt,
                $this->cipher,
                $this->key,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($encrypted === false) {
                throw new \Exception('Encryption failed: ' . openssl_error_string());
            }

            // Format: KeyID:IV:EncryptedData (all base64 encoded)
            $combined = base64_encode($this->active_key_id) . ':' . base64_encode($iv) . ':' . base64_encode($encrypted);
            return $combined;
        } catch (\Exception $e) {
            error_log('GDPR Framework - Encryption Error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Decrypt data with support for key rotation
     */
    public function decrypt($encrypted_data) {
        if (empty($encrypted_data)) {
            return '';
        }

        if (!extension_loaded('openssl')) {
            throw new \Exception('Cannot decrypt data: OpenSSL extension not available');
        }

        try {
            // Split the encrypted data to get the parts
            $parts = explode(':', $encrypted_data);
            
            // Handle both old format (without key_id) and new format
            if (count($parts) === 3) {
                // New format: KeyID:IV:EncryptedData
                $key_id = base64_decode($parts[0]);
                $iv = base64_decode($parts[1]);
                $encrypted = base64_decode($parts[2]);
                
                // Retrieve the key for this data
                $keys = get_option('gdpr_encryption_keys');
                if (!isset($keys['keys'][$key_id])) {
                    throw new \Exception('Encryption key not found for decryption');
                }
                
                $decryption_key = base64_decode($keys['keys'][$key_id]['key']);
            } else if (count($parts) === 1) {
                // Old format: base64 encoded data with IV at beginning
                $decoded = base64_decode($encrypted_data);
                $iv_length = openssl_cipher_iv_length($this->cipher);
                
                if (strlen($decoded) <= $iv_length) {
                    throw new \Exception('Invalid encrypted data format');
                }
                
                $iv = substr($decoded, 0, $iv_length);
                $encrypted = substr($decoded, $iv_length);
                $decryption_key = $this->key;
            } else {
                throw new \Exception('Invalid encrypted data format');
            }

            // Decrypt the data
            $decrypted = openssl_decrypt(
                $encrypted,
                $this->cipher,
                $decryption_key,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($decrypted === false) {
                throw new \Exception('Decryption failed: ' . openssl_error_string());
            }

            // Check if data was serialized
            if ($this->isSerialized($decrypted)) {
                return unserialize($decrypted);
            }

            return $decrypted;
        } catch (\Exception $e) {
            error_log('GDPR Framework - Decryption Error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Rotate encryption key with improved transaction safety
     */
    public function rotateKey() {
        global $wpdb;
        
        // Verify OpenSSL extension
        if (!extension_loaded('openssl')) {
            throw new \Exception('Cannot rotate key: OpenSSL extension not available');
        }
    
        try {
            $wpdb->query('START TRANSACTION');
    
            // Get all existing keys
            $key_data = get_option('gdpr_encryption_keys');
            if (!$key_data || empty($key_data['keys'])) {
                // Initialize if not exists
                $this->initializeKey();
                $key_data = get_option('gdpr_encryption_keys');
            }
            
            // Store old key for decryption
            $old_key_id = $key_data['active_key_id'];
            $old_key = $key_data['keys'][$old_key_id]['key'];
            
            // Generate new key
            $new_key = $this->generateKey();
            $new_key_id = uniqid('key_');
            
            // Add new key to keyring while keeping old keys
            $key_data['keys'][$new_key_id] = [
                'key' => $new_key,
                'created' => time()
            ];
            
            // Update keyring but don't set as active until re-encryption is complete
            update_option('gdpr_encryption_keys', $key_data);
            
            // Get all tables that may contain encrypted data
            $tables = [
                $wpdb->prefix . 'gdpr_user_data',
                // Add other tables containing encrypted data
            ];
    
            // Re-encrypt all data with new key
            foreach ($tables as $table) {
                // First check if table exists to avoid errors
                $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
                if (!$table_exists) {
                    continue;
                }
                
                // Get rows with encrypted data
                $rows = $wpdb->get_results("SELECT * FROM {$table} WHERE encrypted_data IS NOT NULL AND encrypted_data != ''");
                
                foreach ($rows as $row) {
                    // Skip rows with empty encrypted data
                    if (empty($row->encrypted_data)) {
                        continue;
                    }
                    
                    try {
                        // First decrypt with old key
                        $decrypted = null;
                        
                        // Try to decrypt using the current format
                        $parts = explode(':', $row->encrypted_data);
                        if (count($parts) === 3) {
                            // New format - get key_id from data
                            $key_id = base64_decode($parts[0]);
                            $iv = base64_decode($parts[1]);
                            $encrypted = base64_decode($parts[2]);
                            
                            // Get the right key for this data
                            if (isset($key_data['keys'][$key_id])) {
                                $decrypt_key = base64_decode($key_data['keys'][$key_id]['key']);
                                $decrypted = openssl_decrypt(
                                    $encrypted,
                                    $this->cipher,
                                    $decrypt_key,
                                    OPENSSL_RAW_DATA,
                                    $iv
                                );
                            }
                        } else {
                            // Old format - try with current key
                            $decoded = base64_decode($row->encrypted_data);
                            $iv_length = openssl_cipher_iv_length($this->cipher);
                            
                            if (strlen($decoded) > $iv_length) {
                                $iv = substr($decoded, 0, $iv_length);
                                $encrypted = substr($decoded, $iv_length);
                                
                                $decrypted = openssl_decrypt(
                                    $encrypted,
                                    $this->cipher,
                                    base64_decode($old_key),
                                    OPENSSL_RAW_DATA,
                                    $iv
                                );
                            }
                        }
                        
                        // Skip if decryption failed
                        if ($decrypted === false || $decrypted === null) {
                            continue;
                        }
    
                        // Encrypt with new key using new format
                        $iv_length = openssl_cipher_iv_length($this->cipher);
                        $iv = openssl_random_pseudo_bytes($iv_length, $secure);
                        
                        if (!$secure) {
                            throw new \Exception('Failed to generate secure IV for re-encryption');
                        }
                        
                        $encrypted = openssl_encrypt(
                            $decrypted,
                            $this->cipher,
                            base64_decode($new_key),
                            OPENSSL_RAW_DATA,
                            $iv
                        );
                        
                        if ($encrypted === false) {
                            throw new \Exception('Re-encryption failed: ' . openssl_error_string());
                        }
                        
                        // Format: KeyID:IV:EncryptedData (all base64 encoded)
                        $new_encrypted_data = base64_encode($new_key_id) . ':' . base64_encode($iv) . ':' . base64_encode($encrypted);
    
                        // Update record
                        $wpdb->update(
                            $table,
                            ['encrypted_data' => $new_encrypted_data],
                            ['id' => $row->id]
                        );
                    } catch (\Exception $e) {
                        error_log('GDPR Framework - Error re-encrypting row ID ' . $row->id . ': ' . $e->getMessage());
                        // Continue with next row, don't fail the entire operation
                    }
                }
            }
    
            // After all data is successfully re-encrypted, set new key as active
            $key_data['active_key_id'] = $new_key_id;
            update_option('gdpr_encryption_keys', $key_data);
            update_option('gdpr_last_key_rotation', time());
            
            // Update instance variables
            $this->active_key_id = $new_key_id;
            $this->key = base64_decode($new_key);
    
            $wpdb->query('COMMIT');
    
            // Log successful data re-encryption
            do_action('gdpr_data_reencrypted', get_current_user_id());
            
            return true;
    
        } catch (\Exception $e) {
            $wpdb->query('ROLLBACK');
            
            // Log failed data re-encryption
            do_action('gdpr_data_reencryption_failed', get_current_user_id(), $e->getMessage());
            
            error_log('GDPR Framework - Key Rotation Error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if a string is serialized
     */
    private function isSerialized($data) {
        if (!is_string($data)) {
            return false;
        }
        $data = trim($data);
        if ('N;' === $data) {
            return true;
        }
        if (!preg_match('/^([adObis]):/', $data, $badions)) {
            return false;
        }
        switch ($badions[1]) {
            case 'a':
            case 'O':
            case 's':
                if (preg_match("/^{$badions[1]}:[0-9]+:.*[;}]\$/s", $data)) {
                    return true;
                }
                break;
            case 'b':
            case 'i':
            case 'd':
                if (preg_match("/^{$badions[1]}:[0-9.E-]+;\$/", $data)) {
                    return true;
                }
                break;
        }
        return false;
    }
    
    /**
     * Purge old encryption keys that are no longer in use
     * This should be called periodically to clean up unused keys
     */
    public function purgeOldKeys() {
        global $wpdb;
        
        // Get all keys
        $key_data = get_option('gdpr_encryption_keys');
        if (!$key_data || empty($key_data['keys']) || count($key_data['keys']) <= 1) {
            // No keys to purge or only one key exists
            return false;
        }
        
        // Get the active key ID
        $active_key_id = $key_data['active_key_id'];
        
        // Get all tables that may contain encrypted data
        $tables = [
            $wpdb->prefix . 'gdpr_user_data',
            // Add other tables containing encrypted data
        ];
        
        // Find all key IDs in use
        $keys_in_use = [$active_key_id]; // Always keep active key
        
        foreach ($tables as $table) {
            // First check if table exists to avoid errors
            $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
            if (!$table_exists) {
                continue;
            }
            
            // Get rows with encrypted data
            $rows = $wpdb->get_results("SELECT encrypted_data FROM {$table} WHERE encrypted_data IS NOT NULL AND encrypted_data != ''");
            
            foreach ($rows as $row) {
                // Skip rows with empty encrypted data
                if (empty($row->encrypted_data)) {
                    continue;
                }
                
                // Try to extract key ID from data
                $parts = explode(':', $row->encrypted_data);
                if (count($parts) === 3) {
                    $key_id = base64_decode($parts[0]);
                    if ($key_id !== $active_key_id && !in_array($key_id, $keys_in_use)) {
                        $keys_in_use[] = $key_id;
                    }
                }
            }
        }
        
        // Remove keys not in use
        $removed_keys = 0;
        foreach (array_keys($key_data['keys']) as $key_id) {
            if (!in_array($key_id, $keys_in_use)) {
                unset($key_data['keys'][$key_id]);
                $removed_keys++;
            }
        }
        
        // Update key data if keys were removed
        if ($removed_keys > 0) {
            update_option('gdpr_encryption_keys', $key_data);
            return $removed_keys;
        }
        
        return 0;
    }
}
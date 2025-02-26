<?php
if (!defined('ABSPATH')) exit;

// Make sure variables are set to prevent notices
$requirements_info = $requirements_info ?? [];
$requirements_summary = $requirements_summary ?? [];
$database_stats = $database_stats ?? [];
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <?php if (!empty($requirements_summary)): ?>
    <!-- Overall System Status Summary -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('System Status Summary', 'wp-gdpr-framework'); ?></h2>
        <div class="gdpr-system-summary">
            <div class="system-stat-box">
                <span><?php _e('Total Requirements Checked', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value"><?php echo esc_html($requirements_summary['total']); ?></span>
            </div>
            <div class="system-stat-box">
                <span><?php _e('Requirements Met', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value status-success"><?php echo esc_html($requirements_summary['pass']); ?></span>
            </div>
            <div class="system-stat-box">
                <span><?php _e('Warnings', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value status-warning"><?php echo esc_html($requirements_summary['warning']); ?></span>
            </div>
            <div class="system-stat-box">
                <span><?php _e('Errors', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value status-failure"><?php echo esc_html($requirements_summary['error']); ?></span>
            </div>
            <div class="system-stat-box">
                <span><?php _e('Overall Success Rate', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value <?php echo $requirements_summary['success_rate'] > 80 ? 'status-success' : 'status-warning'; ?>">
                    <?php echo esc_html($requirements_summary['success_rate']); ?>%
                </span>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Detailed Requirements -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('System Requirements', 'wp-gdpr-framework'); ?></h2>
        
        <?php if (!empty($requirements_info)): ?>
            <table class="widefat">
                <thead>
                    <tr>
                        <th><?php _e('Requirement', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Minimum', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Recommended', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Current', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Status', 'wp-gdpr-framework'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($requirements_info as $requirement): ?>
                        <tr>
                            <td>
                                <strong><?php echo esc_html($requirement['name']); ?></strong>
                                <?php if (isset($requirement['docs_url'])): ?>
                                    <br><a href="<?php echo esc_url($requirement['docs_url']); ?>" target="_blank">
                                        <?php _e('More info', 'wp-gdpr-framework'); ?> →
                                    </a>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($requirement['min']); ?></td>
                            <td><?php echo esc_html($requirement['recommended']); ?></td>
                            <td><code><?php echo esc_html($requirement['current']); ?></code></td>
                            <td>
                                <?php 
                                $status_class = '';
                                $status_icon = '';
                                
                                switch ($requirement['status']) {
                                    case 'ok':
                                        $status_class = 'status-success';
                                        $status_icon = '✓';
                                        break;
                                    case 'warning':
                                        $status_class = 'status-warning';
                                        $status_icon = '⚠';
                                        break;
                                    case 'error':
                                        $status_class = 'status-failure';
                                        $status_icon = '✗';
                                        break;
                                }
                                ?>
                                <span class="<?php echo esc_attr($status_class); ?>">
                                    <?php echo $status_icon; ?> <?php echo esc_html($requirement['message']); ?>
                                </span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p><?php _e('System requirements checker not available.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>
    </div>
    
    <!-- Database Status -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('Database Status', 'wp-gdpr-framework'); ?></h2>
        
        <?php if (!empty($database_stats)): ?>
            <table class="widefat">
                <thead>
                    <tr>
                        <th><?php _e('Table', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Rows', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Data Size', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Index Size', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Total Size', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Engine', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Last Update', 'wp-gdpr-framework'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($database_stats as $table): ?>
                        <tr>
                            <td><?php echo esc_html($table['name']); ?></td>
                            <td><?php echo esc_html(number_format($table['rows'])); ?></td>
                            <td><?php echo esc_html($table['data_size']); ?></td>
                            <td><?php echo esc_html($table['index_size']); ?></td>
                            <td><?php echo esc_html($table['total_size']); ?></td>
                            <td><?php echo esc_html($table['engine']); ?></td>
                            <td>
                                <?php 
                                echo !empty($table['last_update']) 
                                    ? esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($table['last_update'])))
                                    : __('Unknown', 'wp-gdpr-framework');
                                ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <p>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <?php wp_nonce_field('gdpr_optimize_tables', 'optimize_tables_nonce'); ?>
                    <input type="hidden" name="action" value="gdpr_optimize_tables">
                    <button type="submit" class="button button-secondary">
                        <?php _e('Optimize Tables', 'wp-gdpr-framework'); ?>
                    </button>
                </form>
            </p>
            
        <?php else: ?>
            <p><?php _e('Database stats not available.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>
    </div>
    
    <!-- Caching Status -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('Caching Status', 'wp-gdpr-framework'); ?></h2>
        
        <?php if (isset($caching) && method_exists($caching, 'getCacheInfo')): 
            $cache_info = $caching->getCacheInfo();
        ?>
            <div class="gdpr-cache-info">
                <div class="cache-stat-box">
                    <span><?php _e('Object Caching', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value status-<?php echo $cache_info['enabled'] ? 'success' : 'warning'; ?>">
                        <?php echo $cache_info['enabled'] ? __('Enabled', 'wp-gdpr-framework') : __('Disabled', 'wp-gdpr-framework'); ?>
                    </span>
                </div>
                
                <div class="cache-stat-box">
                    <span><?php _e('Caching System', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value <?php echo $cache_info['persistent'] ? 'status-success' : ''; ?>">
                        <?php echo esc_html(ucfirst($cache_info['type'])); ?>
                    </span>
                </div>
                
                <div class="cache-stat-box">
                    <span><?php _e('Persistent Cache', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value status-<?php echo $cache_info['persistent'] ? 'success' : 'warning'; ?>">
                        <?php echo $cache_info['persistent'] ? __('Yes', 'wp-gdpr-framework') : __('No', 'wp-gdpr-framework'); ?>
                    </span>
                </div>
                
                <div class="cache-stat-box">
                    <span><?php _e('Cache Expiration', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value">
                        <?php echo esc_html($cache_info['expiration'] . ' ' . __('seconds', 'wp-gdpr-framework')); ?>
                    </span>
                </div>
            </div>
            
            <div class="cache-recommendations">
                <?php if (!$cache_info['persistent']): ?>
                    <div class="notice notice-warning inline">
                        <p>
                            <?php _e('Consider using a persistent object cache like Redis or Memcached for better performance.', 'wp-gdpr-framework'); ?>
                        </p>
                    </div>
                <?php endif; ?>
            </div>
            
        <?php else: ?>
            <p><?php _e('Caching information not available.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>
    </div>
    
    <!-- Network Configuration -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('Network Configuration', 'wp-gdpr-framework'); ?></h2>
        
        <?php if (isset($network) && method_exists($network, 'getNetworkInfo')): 
            $network_info = $network->getNetworkInfo();
        ?>
            <div class="gdpr-network-info">
                <div class="network-stat-box">
                    <span><?php _e('Load Balancer', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value">
                        <?php echo $network_info['load_balancer'] ? __('Detected', 'wp-gdpr-framework') : __('Not Detected', 'wp-gdpr-framework'); ?>
                    </span>
                </div>
                
                <div class="network-stat-box">
                    <span><?php _e('CDN', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value status-<?php echo $network_info['cdn_enabled'] ? 'success' : 'warning'; ?>">
                        <?php echo $network_info['cdn_enabled'] ? __('Enabled', 'wp-gdpr-framework') : __('Disabled', 'wp-gdpr-framework'); ?>
                    </span>
                </div>
                
                <?php if ($network_info['cdn_enabled']): ?>
                <div class="network-stat-box">
                    <span><?php _e('CDN URL', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value">
                        <?php echo esc_html($network_info['cdn_url']); ?>
                    </span>
                </div>
                <?php endif; ?>
                
                <div class="network-stat-box">
                    <span><?php _e('Real IP Address', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value">
                        <?php echo esc_html($network_info['real_ip']); ?>
                    </span>
                </div>
            </div>
            
            <div class="network-recommendations">
                <?php if (!$network_info['cdn_enabled']): ?>
                    <div class="notice notice-info inline">
                        <p>
                            <?php _e('Using a CDN can help distribute GDPR policies and assets globally for better performance.', 'wp-gdpr-framework'); ?>
                        </p>
                    </div>
                <?php endif; ?>
                
                <?php if (!$network_info['load_balancer']): ?>
                    <div class="notice notice-info inline">
                        <p>
                            <?php _e('Load balancing can improve reliability and performance for high-traffic sites.', 'wp-gdpr-framework'); ?>
                        </p>
                    </div>
                <?php endif; ?>
            </div>
            
        <?php else: ?>
            <p><?php _e('Network configuration information not available.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>
    </div>
</div>

<style>
    .system-stat-box, .cache-stat-box, .network-stat-box {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px;
        border-bottom: 1px solid #f0f0f1;
    }
    
    .status-success {
        color: #00a32a;
    }
    
    .status-warning {
        color: #f0b849;
    }
    
    .status-failure {
        color: #d63638;
    }
    
    .cache-recommendations, .network-recommendations {
        margin-top: 15px;
    }
</style>
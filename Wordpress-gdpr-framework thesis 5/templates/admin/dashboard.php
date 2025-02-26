<?php
if (!defined('ABSPATH')) exit;

// Initialize variables with defaults
$stats = $stats ?? [];
$database_ok = $database_ok ?? false;
$cleanup_status = $cleanup_status ?? ['next_run' => __('Not scheduled', 'wp-gdpr-framework')];

?>
<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <div class="gdpr-dashboard-grid">
            <!-- New Statistics Section -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('GDPR Statistics', 'wp-gdpr-framework'); ?></h2>
        <div class="stat-box">
            <span><?php _e('Total Users with Consent', 'wp-gdpr-framework'); ?></span>
            <span class="stat-value"><?php echo esc_html($stats['total_consents'] ?? 0); ?></span>
        </div>
        <div class="stat-box">
            <span><?php _e('Pending Requests', 'wp-gdpr-framework'); ?></span>
            <span class="stat-value"><?php echo esc_html($stats['pending_requests'] ?? 0); ?></span>
        </div>
    </div>

    <!-- System Health Section -->
    <div class="gdpr-dashboard-section">
        <h2><?php _e('System Health', 'wp-gdpr-framework'); ?></h2>
        <div class="stat-box">
            <span><?php _e('Database Status', 'wp-gdpr-framework'); ?></span>
            <span class="stat-value status-<?php echo $database_ok ? 'success' : 'failure'; ?>">
                <?php echo $database_ok ? __('OK', 'wp-gdpr-framework') : __('Check Required', 'wp-gdpr-framework'); ?>
            </span>
        </div>
        <div class="stat-box">
            <span><?php _e('Next Scheduled Cleanup', 'wp-gdpr-framework'); ?></span>
            <span class="stat-value"><?php echo esc_html($cleanup_status['next_run']); ?></span>
        </div>
    </div>
        <!-- Consent Overview -->
        <div class="gdpr-dashboard-section">
            <h2><?php _e('Consent Overview', 'wp-gdpr-framework'); ?></h2>
            
            <?php 
            if (isset($consent) && method_exists($consent, 'getConsentStats')):
                $stats = $consent->getConsentStats();
                if (!empty($stats['consent_types'])): 
            ?>
                <table class="widefat consent-overview">
                    <thead>
                        <tr>
                            <th><?php _e('Consent Type', 'wp-gdpr-framework'); ?></th>
                            <th><?php _e('Users', 'wp-gdpr-framework'); ?></th>
                            <th><?php _e('Percentage', 'wp-gdpr-framework'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($stats['consent_types'] as $type): ?>
                            <tr>
                                <td><?php echo esc_html($type['label']); ?></td>
                                <td><?php echo esc_html($type['count']); ?></td>
                                <td><?php echo esc_html($type['percentage']); ?>%</td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p><?php _e('No consent types defined yet.', 'wp-gdpr-framework'); ?></p>
            <?php endif; 
            else: ?>
                <p><?php _e('Consent management not initialized.', 'wp-gdpr-framework'); ?></p>
            <?php endif; ?>
        </div>

        <!-- Data Requests Overview -->
        <div class="gdpr-dashboard-section">
            <h2><?php _e('Data Requests', 'wp-gdpr-framework'); ?></h2>
            <?php if (isset($portability)): 
                $pending_requests = $portability->getPendingRequests();
            ?>
                <div class="stat-box">
                    <span><?php _e('Pending Requests', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value"><?php echo count($pending_requests); ?></span>
                </div>
                <?php if (!empty($pending_requests)): ?>
                    <p><a href="<?php echo admin_url('admin.php?page=gdpr-framework-settings#data-portability'); ?>" 
                          class="button button-primary"><?php _e('Process Requests', 'wp-gdpr-framework'); ?></a></p>
                <?php endif; ?>
            <?php else: ?>
                <p><?php _e('Data portability not initialized.', 'wp-gdpr-framework'); ?></p>
            <?php endif; ?>
        </div>

        <!-- Security Overview -->
        <div class="gdpr-dashboard-section">
            <h2><?php _e('Security Status', 'wp-gdpr-framework'); ?></h2>
            <?php if (isset($encryption)): ?>
                <div class="stat-box">
                    <span><?php _e('Encryption Status', 'wp-gdpr-framework'); ?></span>
                    <?php if (get_option('gdpr_encryption_key')): ?>
                        <span class="stat-value status-success"><?php _e('Active', 'wp-gdpr-framework'); ?></span>
                    <?php else: ?>
                        <span class="stat-value status-failure"><?php _e('Not Configured', 'wp-gdpr-framework'); ?></span>
                    <?php endif; ?>
                </div>
                <div class="stat-box">
                    <span><?php _e('Last Key Rotation', 'wp-gdpr-framework'); ?></span>
                    <span class="stat-value">
                        <?php 
                        $last_rotation = get_option('gdpr_last_key_rotation');
                        echo $last_rotation 
                            ? date_i18n(get_option('date_format'), $last_rotation)
                            : __('Never', 'wp-gdpr-framework');
                        ?>
                    </span>
                </div>
            <?php else: ?>
                <p><?php _e('Encryption not initialized.', 'wp-gdpr-framework'); ?></p>
            <?php endif; ?>
        </div>

        <!-- Recent Activity -->
        <div class="gdpr-dashboard-section">
    <h2><?php _e('Recent Activity', 'wp-gdpr-framework'); ?></h2>
    <?php if (isset($audit)): 
        $stats = $audit->getStats();
        $recent_activities = $audit->getRecentActivities(5);
    ?>
        <div class="gdpr-audit-summary">
            <div class="gdpr-audit-stat">
                <span><?php _e('Total Events', 'wp-gdpr-framework'); ?></span>
                <span class="stat-value"><?php echo number_format($stats['total_entries']); ?></span>
            </div>
            <div class="gdpr-audit-stat">
                <span><?php _e('High Severity Events', 'wp-gdpr-framework'); ?></span>
                <div class="severity-count">
                    <span class="severity-indicator high"></span>
                    <span class="count"><?php echo number_format($stats['by_severity']['high']); ?></span>
                </div>
            </div>
        </div>

        <?php if (!empty($recent_activities)): ?>
            <table class="widefat">
                <tbody>
                    <?php foreach ($recent_activities as $activity): ?>
                        <tr>
                            <td>
                                <span class="activity-icon severity-<?php echo esc_attr($activity->severity); ?>"></span>
                                <?php echo esc_html($activity->action); ?>
                                <div class="activity-meta">
                                    <?php echo esc_html(
                                        date_i18n(
                                            get_option('date_format') . ' ' . get_option('time_format'),
                                            strtotime($activity->timestamp)
                                        )
                                    ); ?>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <a href="<?php echo admin_url('admin.php?page=gdpr-framework-audit'); ?>" class="view-all-logs">
                <?php _e('View All Logs', 'wp-gdpr-framework'); ?> →
            </a>
        <?php else: ?>
            <p><?php _e('No recent activity.', 'wp-gdpr-framework'); ?></p>
        <?php endif;
    else: ?>
        <p><?php _e('Audit log not initialized.', 'wp-gdpr-framework'); ?></p>
    <?php endif; ?>
</div>
</div>
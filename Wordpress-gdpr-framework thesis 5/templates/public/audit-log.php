<?php
if (!defined('ABSPATH')) exit;

// Get parameters from shortcode attributes
$current_page = isset($_GET['audit_page']) ? max(1, absint($_GET['audit_page'])) : 1;
$per_page = isset($atts['limit']) ? absint($atts['limit']) : 10;
$view = isset($atts['view']) ? $atts['view'] : 'own';

// Get logs
$result = isset($result) ? $result : ['logs' => [], 'total' => 0, 'pages' => 0];
$logs = $result['logs'];
$total_pages = $result['pages'];
?>

<div class="gdpr-audit-log">
    <?php if (!empty($logs)): ?>
        <table class="gdpr-table">
            <thead>
                <tr>
                    <th><?php _e('Date', 'wp-gdpr-framework'); ?></th>
                    <?php if ($view === 'all'): ?>
                        <th><?php _e('User', 'wp-gdpr-framework'); ?></th>
                    <?php endif; ?>
                    <th><?php _e('Action', 'wp-gdpr-framework'); ?></th>
                    <th><?php _e('Details', 'wp-gdpr-framework'); ?></th>
                    <th><?php _e('Severity', 'wp-gdpr-framework'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                    <tr>
                        <td><?php echo esc_html(
                            date_i18n(
                                get_option('date_format') . ' ' . get_option('time_format'),
                                strtotime($log->timestamp)
                            )
                        ); ?></td>
                        <?php if ($view === 'all'): ?>
                            <td>
                                <?php echo $log->user_id ? esc_html($log->display_name) : __('System', 'wp-gdpr-framework'); ?>
                            </td>
                        <?php endif; ?>
                        <td><?php echo esc_html($log->action); ?></td>
                        <td><?php echo esc_html($log->details); ?></td>
                        <td>
                            <span class="severity-badge severity-<?php echo esc_attr($log->severity); ?>">
                                <?php echo esc_html(ucfirst($log->severity)); ?>
                            </span>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($total_pages > 1): ?>
            <div class="gdpr-pagination">
                <?php
                echo paginate_links([
                    'base' => add_query_arg('audit_page', '%#%'),
                    'format' => '',
                    'prev_text' => __('&laquo;'),
                    'next_text' => __('&raquo;'),
                    'total' => $total_pages,
                    'current' => $current_page
                ]);
                ?>
            </div>
        <?php endif; ?>
    <?php else: ?>
        <p><?php _e('No audit log entries found.', 'wp-gdpr-framework'); ?></p>
    <?php endif; ?>
</div>
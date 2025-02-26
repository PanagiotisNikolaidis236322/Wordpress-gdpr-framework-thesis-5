<?php
if (!defined('ABSPATH')) exit;
?>
<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <?php if (isset($audit)): ?>
        <!-- Enhanced Filter Form -->
        <div class="gdpr-audit-filters">
        <?php if (current_user_can('manage_options')): ?>
        <!-- Clear Audit Log Form - Separate form -->
        <div class="audit-actions">
            <form method="post" class="clear-audit-log-form">
                <?php wp_nonce_field('gdpr_clear_audit_log', 'clear_audit_nonce'); ?>
                <button type="submit" 
                        name="clear_audit_log" 
                        class="button button-secondary" 
                        onclick="return confirm('<?php esc_attr_e('Are you sure you want to clear all audit log entries? This action cannot be undone.', 'wp-gdpr-framework'); ?>');">
                    <span class="dashicons dashicons-trash" style="vertical-align: middle;"></span>
                    <?php _e('Clear Audit Log', 'wp-gdpr-framework'); ?>
                </button>
            </form>
        </div>
    <?php endif; ?>


            <form method="get" id="audit-filter-form">
                <input type="hidden" name="page" value="gdpr-framework-audit"> 
                <div class="filters-grid">
                    <!-- Severity Filter -->
                    <div class="filter-item">
                        <label for="severity"><?php _e('Severity', 'wp-gdpr-framework'); ?></label>
                        <select name="severity" id="severity">
                            <option value=""><?php _e('All Severities', 'wp-gdpr-framework'); ?></option>
                            <option value="low" <?php selected(isset($_GET['severity']) && $_GET['severity'] === 'low'); ?>>
                                <?php _e('Low', 'wp-gdpr-framework'); ?>
                            </option>
                            <option value="medium" <?php selected(isset($_GET['severity']) && $_GET['severity'] === 'medium'); ?>>
                                <?php _e('Medium', 'wp-gdpr-framework'); ?>
                            </option>
                            <option value="high" <?php selected(isset($_GET['severity']) && $_GET['severity'] === 'high'); ?>>
                                <?php _e('High', 'wp-gdpr-framework'); ?>
                            </option>
                        </select>
                    </div>

                    <!-- Date Range Filters -->
                    <div class="filter-item">
                        <label for="from_date"><?php _e('From Date', 'wp-gdpr-framework'); ?></label>
                        <input type="date" id="from_date" name="from_date" 
                               value="<?php echo isset($_GET['from_date']) ? esc_attr($_GET['from_date']) : ''; ?>">
                    </div>

                    <div class="filter-item">
                        <label for="to_date"><?php _e('To Date', 'wp-gdpr-framework'); ?></label>
                        <input type="date" id="to_date" name="to_date"
                               value="<?php echo isset($_GET['to_date']) ? esc_attr($_GET['to_date']) : ''; ?>">
                    </div>

                    <!-- User Filter -->
                    <?php if (current_user_can('list_users')): ?>
<div class="filter-item">
    <label for="user_id"><?php _e('User', 'wp-gdpr-framework'); ?></label>
    <select name="user_id" id="user_id" class="regular-dropdown">
        <option value=""><?php _e('All Users', 'wp-gdpr-framework'); ?></option>
        <?php 
        // Get all users with custom query
        $users = get_users([
            'orderby' => 'display_name',
            'order' => 'ASC',
            'fields' => ['ID', 'display_name'] // Only get needed fields
        ]);

        $selected_user = isset($_GET['user_id']) ? absint($_GET['user_id']) : 0;
        
        foreach ($users as $user) {
            printf(
                '<option value="%d" %s>%s</option>',
                $user->ID,
                selected($selected_user, $user->ID, false),
                esc_html($user->display_name)
            );
        }
        ?>
    </select>
</div>
<?php endif; ?>

                    <!-- Action Buttons -->
                    <div class="filter-actions">
                        <button type="submit" class="button"><?php _e('Apply Filters', 'wp-gdpr-framework'); ?></button>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=gdpr-framework-audit')); ?>" 
                           class="button-link"><?php _e('Clear Filters', 'wp-gdpr-framework'); ?></a>
                    </div>

                    <!-- Export Button -->
                    <?php if (current_user_can('view_gdpr_audit_log')): ?>
                    <div class="filter-actions">
                        <a href="<?php echo wp_nonce_url(
                            add_query_arg([
                                'action' => 'gdpr_export_audit_log',
                                'severity' => $_GET['severity'] ?? '',
                                'from_date' => $_GET['from_date'] ?? '',
                                'to_date' => $_GET['to_date'] ?? '',
                                'user_id' => $_GET['user_id'] ?? ''
                            ], admin_url('admin-post.php')),
                            'gdpr_export_audit_log'
                        ); ?>" class="button">
                            <span class="dashicons dashicons-download"></span>
                            <?php _e('Export Filtered Logs', 'wp-gdpr-framework'); ?>
                        </a>
                    </div>
                    <?php endif; ?>
                </div>
            </form>
        </div>

        <?php
        // Get current page number
        $current_page = max(1, isset($_GET['paged']) ? absint($_GET['paged']) : 1);
        $per_page = 20; // Items per page

        // Get logs with pagination
        $result = $audit->getAuditLog([
            'user_id' => isset($_GET['user_id']) ? absint($_GET['user_id']) : null,
            'severity' => isset($_GET['severity']) ? sanitize_text_field($_GET['severity']) : null,
            'from_date' => isset($_GET['from_date']) ? sanitize_text_field($_GET['from_date']) : null,
            'to_date' => isset($_GET['to_date']) ? sanitize_text_field($_GET['to_date']) : null,
            'limit' => $per_page,
            'offset' => ($current_page - 1) * $per_page
        ]);

        if (!empty($result['logs'])):
        ?>
            <!-- Results Summary -->
            <div class="tablenav top">
                <div class="tablenav-pages">
                    <span class="displaying-num">
                        <?php printf(
                            _n('%s item', '%s items', $result['total'], 'wp-gdpr-framework'),
                            number_format_i18n($result['total'])
                        ); ?>
                    </span>
                    <?php
                    echo paginate_links([
                        'base' => add_query_arg('paged', '%#%'),
                        'format' => '',
                        'prev_text' => __('&laquo;'),
                        'next_text' => __('&raquo;'),
                        'total' => $result['pages'],
                        'current' => $current_page
                    ]);
                    ?>
                </div>
            </div>

<table class="widefat fixed striped">  <!-- Added "fixed" class -->
    <thead>
        <tr>
            <th scope="col" class="column-timestamp" style="width: 15%;">
                <?php _e('Date', 'wp-gdpr-framework'); ?>
            </th>
            <th scope="col" class="column-user" style="width: 15%;">
                <?php _e('User', 'wp-gdpr-framework'); ?>
            </th>
            <th scope="col" class="column-action" style="width: 15%;">
                <?php _e('Action', 'wp-gdpr-framework'); ?>
            </th>
            <th scope="col" class="column-details" style="width: 35%;">
                <?php _e('Details', 'wp-gdpr-framework'); ?>
            </th>
            <th scope="col" class="column-severity" style="width: 10%;">
                <?php _e('Severity', 'wp-gdpr-framework'); ?>
            </th>
            <th scope="col" class="column-ip" style="width: 10%;">
                <?php _e('IP Address', 'wp-gdpr-framework'); ?>
            </th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($result['logs'] as $log): ?>
            <tr>
                <td class="column-timestamp has-row-actions">
                    <?php 
                    echo esc_html(
                        date_i18n(
                            get_option('date_format') . ' ' . get_option('time_format'),
                            strtotime($log->timestamp)
                        )
                    ); 
                    ?>
                </td>
                <td class="column-user has-row-actions">
                    <?php
                    if ($log->user_id) {
                        $user = get_userdata($log->user_id);
                        if ($user) {
                            echo '<strong>' . esc_html($user->display_name) . '</strong>';
                            if (current_user_can('edit_users')) {
                                echo '<div class="row-actions">';
                                echo '<span class="edit"><a href="' . esc_url(get_edit_user_link($log->user_id)) . '">' . 
                                     esc_html__('Edit', 'wp-gdpr-framework') . '</a></span>';
                                echo '</div>';
                            }
                        } else {
                            echo '<em>' . esc_html__('Deleted User', 'wp-gdpr-framework') . '</em>';
                        }
                    } else {
                        echo '<em>' . esc_html__('System', 'wp-gdpr-framework') . '</em>';
                    }
                    ?>
                </td>
                <td class="column-action">
                    <?php echo esc_html($log->action); ?>
                </td>
                <td class="column-details">
                    <div class="log-details-text">
                        <?php echo esc_html($log->details); ?>
                    </div>
                </td>
                <td class="column-severity">
                    <span class="severity-badge severity-<?php echo esc_attr($log->severity); ?>">
                        <?php echo esc_html(ucfirst($log->severity)); ?>
                    </span>
                </td>
                <td class="column-ip">
                    <?php echo esc_html($log->ip_address); ?>
                    <?php if (!empty($log->user_agent)): ?>
                        <div class="user-agent-wrapper">
                            <span class="user-agent-info" title="<?php echo esc_attr($log->user_agent); ?>">
                                <span class="dashicons dashicons-info"></span>
                            </span>
                        </div>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>

            <!-- Bottom Pagination -->
            <div class="tablenav bottom">
                <div class="tablenav-pages">
                    <?php
                    echo paginate_links([
                        'base' => add_query_arg('paged', '%#%'),
                        'format' => '',
                        'prev_text' => __('&laquo;'),
                        'next_text' => __('&raquo;'),
                        'total' => $result['pages'],
                        'current' => $current_page
                    ]);
                    ?>
                </div>
            </div>

        <?php else: ?>
            <p><?php _e('No audit log entries found matching your criteria.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>

    <?php else: ?>
        <div class="notice notice-error">
            <p><?php _e('Audit component not initialized.', 'wp-gdpr-framework'); ?></p>
        </div>
    <?php endif; ?>
</div>
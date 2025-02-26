<?php
if (!defined('ABSPATH')) exit;

// Ensure user is logged in
if (!is_user_logged_in()) {
    echo '<div class="gdpr-notice gdpr-error">';
    echo '<p>' . esc_html__('Please log in to access your privacy dashboard.', 'wp-gdpr-framework') . '</p>';
    echo '<p><a href="' . esc_url(wp_login_url(get_permalink())) . '" class="button">' . 
         esc_html__('Log In', 'wp-gdpr-framework') . '</a></p>';
    echo '</div>';
    return;
}

$user_id = get_current_user_id();
?>

<div class="gdpr-privacy-dashboard">
    <h2><?php _e('Privacy Dashboard', 'wp-gdpr-framework'); ?></h2>
    
    <!-- Consent Management Section -->
    <div class="gdpr-section">
        <h3><?php _e('Your Privacy Choices', 'wp-gdpr-framework'); ?></h3>
        <?php 
        if (isset($consent_types) && !empty($consent_types)): 
            echo do_shortcode('[gdpr_consent_form]');
        else:
        ?>
            <p><?php _e('No consent options are currently available.', 'wp-gdpr-framework'); ?></p>
        <?php endif; ?>
    </div>

    <!-- Data Export Section -->
    <div class="gdpr-section">
        <h3><?php _e('Export Your Data', 'wp-gdpr-framework'); ?></h3>
        <p><?php _e('Download a copy of your personal data in your preferred format.', 'wp-gdpr-framework'); ?></p>
        
        <form id="gdpr-export-form" class="gdpr-form">
            <?php wp_nonce_field('gdpr_nonce', 'gdpr_nonce'); ?>
            
            <div class="gdpr-form-row">
                <label>
                    <?php _e('Export Format', 'wp-gdpr-framework'); ?>
                    <select name="export_format">
                        <?php
                        $formats = get_option('gdpr_export_formats', ['json']);
                        foreach ($formats as $format):
                        ?>
                            <option value="<?php echo esc_attr($format); ?>">
                                <?php echo esc_html(strtoupper($format)); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </label>
            </div>

            <div class="gdpr-form-row">
                <button type="submit" class="button button-primary">
                    <?php _e('Request Data Export', 'wp-gdpr-framework'); ?>
                </button>
            </div>

            <div class="gdpr-notice" style="display: none;"></div>
        </form>

        <?php if (!empty($recent_exports)): ?>
            <div class="gdpr-recent-exports">
                <h4><?php _e('Recent Export Requests', 'wp-gdpr-framework'); ?></h4>
                <table class="gdpr-table">
                    <thead>
                        <tr>
                            <th><?php _e('Date', 'wp-gdpr-framework'); ?></th>
                            <th><?php _e('Status', 'wp-gdpr-framework'); ?></th>
                            <th><?php _e('Actions', 'wp-gdpr-framework'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_exports as $export): ?>
                            <tr>
                                <td>
                                    <?php echo esc_html(
                                        date_i18n(
                                            get_option('date_format') . ' ' . get_option('time_format'),
                                            strtotime($export->created_at)
                                        )
                                    ); ?>
                                </td>
                                <td>
                                    <span class="gdpr-status gdpr-status-<?php echo esc_attr($export->status); ?>">
                                        <?php echo esc_html(ucfirst($export->status)); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($export->status === 'completed'): ?>
                                        <a href="<?php echo esc_url(add_query_arg([
                                            'action' => 'gdpr_download_export',
                                            'request_id' => $export->id,
                                            'nonce' => wp_create_nonce('gdpr_download_' . $export->id)
                                        ], admin_url('admin-ajax.php'))); ?>" 
                                           class="button button-secondary">
                                            <?php _e('Download', 'wp-gdpr-framework'); ?>
                                        </a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <!-- Data Erasure Section -->
    <div class="gdpr-section">
        <h3><?php _e('Data Erasure', 'wp-gdpr-framework'); ?></h3>
        <p><?php _e('Request deletion of your personal data. Please note that this action cannot be undone.', 'wp-gdpr-framework'); ?></p>
        
        <form id="gdpr-erasure-form" class="gdpr-form">
            <?php wp_nonce_field('gdpr_nonce', 'gdpr_nonce'); ?>
            
            <div class="gdpr-form-row">
                <label>
                    <input type="checkbox" name="confirm_erasure" required>
                    <?php _e('I understand that this will permanently delete my personal data and cannot be undone.', 'wp-gdpr-framework'); ?>
                </label>
            </div>

            <div class="gdpr-form-row">
                <button type="submit" class="button button-danger">
                    <?php _e('Request Data Erasure', 'wp-gdpr-framework'); ?>
                </button>
            </div>

            <div class="gdpr-notice" style="display: none;"></div>
        </form>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    // Handle data export request
    $('#gdpr-export-form').on('submit', function(e) {
        e.preventDefault();
        
        const $form = $(this);
        const $notice = $form.find('.gdpr-notice');
        const $submit = $form.find('button[type="submit"]');
        
        $.ajax({
            url: gdprFramework.ajaxUrl,
            method: 'POST',
            data: {
                action: 'gdpr_export_data',
                format: $form.find('select[name="export_format"]').val(),
                nonce: $form.find('input[name="gdpr_nonce"]').val()
            },
            beforeSend: function() {
                $submit.prop('disabled', true);
                $notice.removeClass('gdpr-error gdpr-success').hide();
            },
            success: function(response) {
                if (response.success) {
                    $notice.addClass('gdpr-success')
                           .html(response.data.message)
                           .show();
                    if (response.data.download_url) {
                        window.location.href = response.data.download_url;
                    }
                    setTimeout(function() {
                        location.reload();
                    }, 2000);
                } else {
                    $notice.addClass('gdpr-error')
                           .html(response.data)
                           .show();
                }
            },
            error: function() {
                $notice.addClass('gdpr-error')
                       .html('<?php echo esc_js(__('An error occurred. Please try again.', 'wp-gdpr-framework')); ?>')
                       .show();
            },
            complete: function() {
                $submit.prop('disabled', false);
            }
        });
    });

    // Handle data erasure request
    $('#gdpr-erasure-form').on('submit', function(e) {
        e.preventDefault();
        
        if (!confirm('<?php echo esc_js(__('Are you absolutely sure you want to request deletion of your personal data? This action cannot be undone.', 'wp-gdpr-framework')); ?>')) {
            return;
        }
        
        const $form = $(this);
        const $notice = $form.find('.gdpr-notice');
        const $submit = $form.find('button[type="submit"]');
        
        $.ajax({
            url: gdprFramework.ajaxUrl,
            method: 'POST',
            data: {
                action: 'gdpr_erase_data',
                nonce: $form.find('input[name="gdpr_nonce"]').val()
            },
            beforeSend: function() {
                $submit.prop('disabled', true);
                $notice.removeClass('gdpr-error gdpr-success').hide();
            },
            success: function(response) {
                if (response.success) {
                    $notice.addClass('gdpr-success')
                           .html(response.data.message)
                           .show();
                    $form.find('input[type="checkbox"]').prop('checked', false);
                    setTimeout(function() {
                        window.location.href = '<?php echo esc_js(wp_logout_url(home_url())); ?>';
                    }, 3000);
                } else {
                    $notice.addClass('gdpr-error')
                           .html(response.data)
                           .show();
                }
            },
            error: function() {
                $notice.addClass('gdpr-error')
                       .html('<?php echo esc_js(__('An error occurred. Please try again.', 'wp-gdpr-framework')); ?>')
                       .show();
            },
            complete: function() {
                $submit.prop('disabled', false);
            }
        });
    });
});
</script>
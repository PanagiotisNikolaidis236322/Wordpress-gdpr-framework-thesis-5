<?php
/**
 * GDPR Framework Settings Template
 * 
 * Displays the main settings interface for the GDPR Framework plugin.
 * Aligned with Appendix B documentation structure.
 *
 * @package WordPress GDPR Framework
 */

if (!defined('ABSPATH')) exit;
?>
<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <?php settings_errors(); ?>

    <!-- Tab Navigation -->
    <div class="nav-tab-wrapper">
        <a href="#general" class="nav-tab nav-tab-active" data-tab="general">
            <?php _e('General', 'wp-gdpr-framework'); ?>
        </a>
        <a href="#enforcement" class="nav-tab" data-tab="enforcement">
            <?php _e('Enforcement Mode', 'wp-gdpr-framework'); ?>
        </a>
        <a href="#consent" class="nav-tab" data-tab="consent">
            <?php _e('Consent Management', 'wp-gdpr-framework'); ?>
        </a>
        <a href="#user-rights" class="nav-tab" data-tab="user-rights">
            <?php _e('User Rights', 'wp-gdpr-framework'); ?>
        </a>
        <a href="#security" class="nav-tab" data-tab="security">
            <?php _e('Security & Compliance', 'wp-gdpr-framework'); ?>
        </a>
        <a href="#audit" class="nav-tab" data-tab="audit">
            <?php _e('Audit & Reports', 'wp-gdpr-framework'); ?>
        </a>
    </div>

    <form method="post" action="options.php" class="gdpr-settings-form">
        <?php 
        settings_fields('gdpr_framework_settings');
        $consent_types = get_option('gdpr_consent_types', []); 
        ?>
        
        <!-- General Settings Tab -->
        <div id="general" class="tab-content">
            <h2><?php _e('General Settings', 'wp-gdpr-framework'); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="gdpr_privacy_policy_page">
                            <?php _e('Privacy Policy Page', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <?php
                        wp_dropdown_pages([
                            'name' => 'gdpr_privacy_policy_page',
                            'id' => 'gdpr_privacy_policy_page',
                            'show_option_none' => __('Select a page', 'wp-gdpr-framework'),
                            'option_none_value' => '0',
                            'selected' => get_option('gdpr_privacy_policy_page', 0)
                        ]);
                        ?>
                        <p class="description">
                            <?php _e('Select the page containing your privacy policy.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_dpo_email">
                            <?php _e('Data Protection Officer Email', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="email" 
                               id="gdpr_dpo_email"
                               name="gdpr_dpo_email" 
                               value="<?php echo esc_attr(get_option('gdpr_dpo_email', '')); ?>"
                               class="regular-text">
                        <p class="description">
                            <?php _e('Email address of your organization\'s Data Protection Officer.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_retention_days">
                            <?php _e('Data Retention Period (days)', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="number" 
                               id="gdpr_retention_days"
                               name="gdpr_retention_days" 
                               value="<?php echo esc_attr(get_option('gdpr_retention_days', 365)); ?>"
                               min="30"
                               class="regular-text">
                        <p class="description">
                            <?php _e('Number of days to retain user data before automatic cleanup.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- GDPR Enforcement Mode Tab -->
        <div id="enforcement" class="tab-content" style="display: none;">
            <h2><?php _e('GDPR Enforcement Mode', 'wp-gdpr-framework'); ?></h2>
            <p class="description">
                <?php _e('Select the level of GDPR compliance enforcement for your site.', 'wp-gdpr-framework'); ?>
            </p>
            
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('Enforcement Mode', 'wp-gdpr-framework'); ?></th>
                    <td>
                        <fieldset>
                            <legend class="screen-reader-text">
                                <?php _e('Enforcement Mode', 'wp-gdpr-framework'); ?>
                            </legend>
                            <label>
                                <input type="radio" 
                                       name="gdpr_enforcement_mode" 
                                       value="basic"
                                       <?php checked(get_option('gdpr_enforcement_mode', 'basic'), 'basic'); ?>>
                                <?php _e('Basic Mode', 'wp-gdpr-framework'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Pre-configured compliance settings suitable for most websites.', 'wp-gdpr-framework'); ?>
                            </p>
                            <br>
                            <label>
                                <input type="radio" 
                                       name="gdpr_enforcement_mode" 
                                       value="advanced"
                                       <?php checked(get_option('gdpr_enforcement_mode', 'basic'), 'advanced'); ?>>
                                <?php _e('Advanced Mode', 'wp-gdpr-framework'); ?>
                            </label>
                            <p class="description">
                                <?php _e('Granular customization for specific data processing policies.', 'wp-gdpr-framework'); ?>
                            </p>
                        </fieldset>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Consent Management Tab -->
        <div id="consent" class="tab-content" style="display: none;">
            <h2><?php _e('Consent Management', 'wp-gdpr-framework'); ?></h2>
            <p class="description">
                <?php _e('Configure cookie banner settings and define consent categories.', 'wp-gdpr-framework'); ?>
            </p>
            
            <!-- Cookie Banner Settings -->
            <h3><?php _e('Cookie Banner Settings', 'wp-gdpr-framework'); ?></h3>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="gdpr_enable_cookie_banner">
                            <?php _e('Enable Cookie Banner', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_enable_cookie_banner"
                               name="gdpr_enable_cookie_banner" 
                               value="1"
                               <?php checked(get_option('gdpr_enable_cookie_banner', 0), 1); ?>>
                        <p class="description">
                            <?php _e('Display a GDPR-compliant cookie consent banner to users.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_cookie_expiry">
                            <?php _e('Cookie Consent Expiration', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="number" 
                               id="gdpr_cookie_expiry"
                               name="gdpr_cookie_expiry" 
                               value="<?php echo esc_attr(get_option('gdpr_cookie_expiry', 30)); ?>"
                               min="1"
                               max="365"
                               class="small-text">
                        <?php _e('days', 'wp-gdpr-framework'); ?>
                        <p class="description">
                            <?php _e('Number of days until the user consent expires and needs renewal.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
            </table>
            
            <!-- Consent Types -->
            <h3><?php _e('Consent Categories', 'wp-gdpr-framework'); ?></h3>
            <p class="description">
                <?php _e('Define different types of consent that users can give or withdraw.', 'wp-gdpr-framework'); ?>
            </p>
            
            <div id="consent-types">
            <?php 
if (!empty($consent_types)):
    foreach ($consent_types as $key => $type):
        // Ensure $type is an array
        $type = is_array($type) ? $type : [];
?>
    <div class="consent-type-item">
        <div class="consent-type-header">
            <input type="text"
                   name="gdpr_consent_types[<?php echo esc_attr($key); ?>][label]"
                   value="<?php echo esc_attr(isset($type['label']) ? $type['label'] : ''); ?>"
                   class="regular-text"
                   placeholder="<?php _e('Consent Type Label', 'wp-gdpr-framework'); ?>"
                   required>
            
            <label class="required-checkbox">
                <input type="checkbox"
                       name="gdpr_consent_types[<?php echo esc_attr($key); ?>][required]"
                       value="1"
                       <?php checked(!empty($type['required'])); ?>>
                <?php _e('Required', 'wp-gdpr-framework'); ?>
            </label>
            
            <button type="button" class="button remove-consent-type">
                <?php _e('Remove', 'wp-gdpr-framework'); ?>
            </button>
        </div>
        
        <textarea name="gdpr_consent_types[<?php echo esc_attr($key); ?>][description]"
                  class="large-text"
                  placeholder="<?php _e('Description', 'wp-gdpr-framework'); ?>"
                  required><?php echo esc_textarea(isset($type['description']) ? $type['description'] : ''); ?></textarea>
    </div>
<?php
    endforeach;
endif;
?>
            </div>

            <button type="button" class="button button-secondary" id="add-consent-type">
                <?php _e('Add Consent Type', 'wp-gdpr-framework'); ?>
            </button>
            
            <!-- Consent Logging Settings -->
            <h3><?php _e('Consent Logging & Version Control', 'wp-gdpr-framework'); ?></h3>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="gdpr_enable_consent_logging">
                            <?php _e('Enable Time-Stamped Consent Logging', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_enable_consent_logging"
                               name="gdpr_enable_consent_logging" 
                               value="1"
                               <?php checked(get_option('gdpr_enable_consent_logging', 1), 1); ?>>
                        <p class="description">
                            <?php _e('Record timestamp, IP address, and user agent when consent is given or withdrawn.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_enable_version_control">
                            <?php _e('Enable Consent Policy Version Control', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_enable_version_control"
                               name="gdpr_enable_version_control" 
                               value="1"
                               <?php checked(get_option('gdpr_enable_version_control', 1), 1); ?>>
                        <p class="description">
                            <?php _e('Keep track of changes to consent policy and prompt users to renew consent when policies change.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- User Rights Management Tab -->
        <div id="user-rights" class="tab-content" style="display: none;">
            <h2><?php _e('User Rights Automation', 'wp-gdpr-framework'); ?></h2>
            <p class="description">
                <?php _e('Configure how user data access, modification, and deletion requests are handled.', 'wp-gdpr-framework'); ?>
            </p>
            
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="gdpr_enable_self_service">
                            <?php _e('Enable Self-Service User Requests', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_enable_self_service"
                               name="gdpr_enable_self_service" 
                               value="1"
                               <?php checked(get_option('gdpr_enable_self_service', 1), 1); ?>>
                        <p class="description">
                            <?php _e('Allow users to submit their own data access, modification, and deletion requests.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_auto_approve_verified">
                            <?php _e('Auto-Approve Verified User Requests', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_auto_approve_verified"
                               name="gdpr_auto_approve_verified" 
                               value="1"
                               <?php checked(get_option('gdpr_auto_approve_verified', 0), 1); ?>>
                        <p class="description">
                            <?php _e('Automatically approve data requests from logged-in verified users.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_export_formats">
                            <?php _e('Data Export Formats', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <?php 
                        $allowed_formats = get_option('gdpr_export_formats', ['json']);
                        $formats = [
                            'json' => 'JSON',
                            'xml' => 'XML',
                            'csv' => 'CSV'
                        ];
                        ?>
                        <fieldset>
                            <legend class="screen-reader-text">
                                <?php _e('Data Export Formats', 'wp-gdpr-framework'); ?>
                            </legend>
                            <?php foreach ($formats as $value => $label): ?>
                                <label>
                                    <input type="checkbox" 
                                           name="gdpr_export_formats[]" 
                                           value="<?php echo esc_attr($value); ?>"
                                           <?php checked(in_array($value, $allowed_formats)); ?>>
                                    <?php echo esc_html($label); ?>
                                </label><br>
                            <?php endforeach; ?>
                            <p class="description">
                                <?php _e('Select available formats for data export.', 'wp-gdpr-framework'); ?>
                            </p>
                        </fieldset>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_export_expiry">
                            <?php _e('Export Expiry', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="number" 
                               id="gdpr_export_expiry"
                               name="gdpr_export_expiry" 
                               value="<?php echo esc_attr(get_option('gdpr_export_expiry', 48)); ?>"
                               min="1" 
                               max="168"
                               class="small-text">
                        <?php _e('hours', 'wp-gdpr-framework'); ?>
                        <p class="description">
                            <?php _e('How long exported data files are kept before automatic deletion (1-168 hours).', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
            </table>
            
            <h3><?php _e('Privacy Portal Shortcodes', 'wp-gdpr-framework'); ?></h3>
            <p class="description">
                <?php _e('Use these shortcodes to display privacy management features on your site.', 'wp-gdpr-framework'); ?>
            </p>
            
            <table class="widefat">
                <thead>
                    <tr>
                        <th><?php _e('Shortcode', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Description', 'wp-gdpr-framework'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>[gdpr_consent_form]</code></td>
                        <td><?php _e('Displays a form for users to manage their consent preferences.', 'wp-gdpr-framework'); ?></td>
                    </tr>
                    <tr>
                        <td><code>[gdpr_privacy_dashboard]</code></td>
                        <td><?php _e('Displays a comprehensive dashboard for users to manage all privacy settings.', 'wp-gdpr-framework'); ?></td>
                    </tr>
                    <tr>
                        <td><code>[gdpr_audit_log]</code></td>
                        <td><?php _e('Displays a log of user\'s privacy-related actions.', 'wp-gdpr-framework'); ?></td>
                    </tr>
                </tbody>
            </table>

            <?php if (!empty($portability) && $portability instanceof \GDPRFramework\Components\DataPortabilityManager): ?>
                <h3><?php _e('Pending Data Requests', 'wp-gdpr-framework'); ?></h3>
                <?php 
                $pending_requests = $portability->getRequestsWithUsers();
                if (!empty($pending_requests)): 
                ?>
                    <table class="widefat">
                        <thead>
                            <tr>
                                <th><?php _e('User', 'wp-gdpr-framework'); ?></th>
                                <th><?php _e('Email', 'wp-gdpr-framework'); ?></th>
                                <th><?php _e('Request Type', 'wp-gdpr-framework'); ?></th>
                                <th><?php _e('Status', 'wp-gdpr-framework'); ?></th>
                                <th><?php _e('Requested', 'wp-gdpr-framework'); ?></th>
                                <th><?php _e('Actions', 'wp-gdpr-framework'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($pending_requests as $request): ?>
                                <tr>
                                    <td><?php echo esc_html($request->display_name); ?></td>
                                    <td><?php echo esc_html($request->user_email); ?></td>
                                    <td>
                                        <?php if ($request->request_type === 'export'): ?>
                                            <span class="dashicons dashicons-download"></span>
                                        <?php else: ?>
                                            <span class="dashicons dashicons-trash"></span>
                                        <?php endif; ?>
                                        <?php echo esc_html(ucfirst($request->request_type)); ?>
                                    </td>
                                    <td>
                                        <span class="status-<?php echo esc_attr($request->status); ?>">
                                            <?php echo esc_html(ucfirst($request->status)); ?>
                                            </span>
                                    </td>
                                    <td>
                                        <?php echo esc_html(
                                            date_i18n(
                                                get_option('date_format') . ' ' . get_option('time_format'),
                                                strtotime($request->created_at)
                                            )
                                        ); ?>
                                    </td>
                                    <td>
                                        <button type="button" 
                                                class="button process-request"
                                                data-id="<?php echo esc_attr($request->id); ?>"
                                                data-type="<?php echo esc_attr($request->request_type); ?>"
                                                data-nonce="<?php echo wp_create_nonce('gdpr_process_request'); ?>">
                                            <?php _e('Process Request', 'wp-gdpr-framework'); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <p><?php _e('No pending requests.', 'wp-gdpr-framework'); ?></p>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <!-- Security & Compliance Tab -->
        <div id="security" class="tab-content" style="display: none;">
            <h2><?php _e('Security & Data Protection', 'wp-gdpr-framework'); ?></h2>
            
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="gdpr_enable_encryption">
                            <?php _e('Enable AES-256 Encryption', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_enable_encryption"
                               name="gdpr_enable_encryption" 
                               value="1"
                               <?php checked(get_option('gdpr_enable_encryption', 1), 1); ?>>
                        <p class="description">
                            <?php _e('Encrypt stored user data with AES-256 encryption.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Encryption Status', 'wp-gdpr-framework'); ?></th>
                    <td>
                        <?php
                        $key_exists = get_option('gdpr_encryption_key') ? true : false;
                        if ($key_exists):
                        ?>
                            <div class="notice notice-success inline">
                                <p><?php _e('Encryption is properly configured.', 'wp-gdpr-framework'); ?></p>
                            </div>
                        <?php else: ?>
                            <div class="notice notice-error inline">
                                <p><?php _e('Encryption key not configured.', 'wp-gdpr-framework'); ?></p>
                            </div>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Key Rotation', 'wp-gdpr-framework'); ?></th>
                    <td>
                        <button type="button" 
                                id="gdpr-rotate-key" 
                                class="button button-secondary"
                                <?php echo !$key_exists ? 'disabled' : ''; ?>>
                            <?php _e('Rotate Encryption Key', 'wp-gdpr-framework'); ?>
                        </button>
                        <p class="description">
                            <?php _e('Rotating the encryption key will re-encrypt all sensitive data with a new key. This operation may take some time.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('Last Key Rotation', 'wp-gdpr-framework'); ?></th>
                    <td>
                        <?php
                        $last_rotation = get_option('gdpr_last_key_rotation');
                        echo $last_rotation 
                            ? esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $last_rotation))
                            : __('Never', 'wp-gdpr-framework');
                        ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_auto_key_rotation">
                            <?php _e('Automatic Key Rotation', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <select name="gdpr_auto_key_rotation" id="gdpr_auto_key_rotation">
                            <option value="0" <?php selected(get_option('gdpr_auto_key_rotation', 0), 0); ?>><?php _e('Disabled', 'wp-gdpr-framework'); ?></option>
                            <option value="30" <?php selected(get_option('gdpr_auto_key_rotation', 0), 30); ?>><?php _e('Every 30 days', 'wp-gdpr-framework'); ?></option>
                            <option value="90" <?php selected(get_option('gdpr_auto_key_rotation', 0), 90); ?>><?php _e('Every 90 days', 'wp-gdpr-framework'); ?></option>
                            <option value="180" <?php selected(get_option('gdpr_auto_key_rotation', 0), 180); ?>><?php _e('Every 180 days', 'wp-gdpr-framework'); ?></option>
                        </select>
                        <p class="description">
                            <?php _e('Set a schedule for automatic encryption key rotation.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
            </table>
            
            <h3><?php _e('Access Control Settings', 'wp-gdpr-framework'); ?></h3>
            
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="gdpr_max_login_attempts">
                            <?php _e('Maximum Login Attempts', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="number" 
                               id="gdpr_max_login_attempts"
                               name="gdpr_max_login_attempts" 
                               value="<?php echo esc_attr(get_option('gdpr_max_login_attempts', 5)); ?>"
                               min="1" 
                               max="10"
                               class="small-text">
                        <p class="description">
                            <?php _e('Number of failed attempts before temporary lockout.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_lockout_duration">
                            <?php _e('Lockout Duration (seconds)', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="number" 
                               id="gdpr_lockout_duration"
                               name="gdpr_lockout_duration" 
                               value="<?php echo esc_attr(get_option('gdpr_lockout_duration', 900)); ?>"
                               min="300" 
                               step="60"
                               class="regular-text">
                        <p class="description">
                            <?php _e('How long users are locked out after exceeding maximum attempts.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Audit & Compliance Reports Tab -->
        <div id="audit" class="tab-content" style="display: none;">
            <h2><?php _e('Audit Logging & Compliance Reports', 'wp-gdpr-framework'); ?></h2>
            <p class="description">
                <?php _e('Configure audit logging and generate reports for regulatory compliance.', 'wp-gdpr-framework'); ?>
            </p>
            
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="gdpr_enable_tamper_protection">
                            <?php _e('Enable Tamper-Proof Logging', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_enable_tamper_protection"
                               name="gdpr_enable_tamper_protection" 
                               value="1"
                               <?php checked(get_option('gdpr_enable_tamper_protection', 1), 1); ?>>
                        <p class="description">
                            <?php _e('Protect audit logs with SHA-512 hash protection.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_audit_retention_days">
                            <?php _e('Audit Log Retention', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="number" 
                               id="gdpr_audit_retention_days"
                               name="gdpr_audit_retention_days" 
                               value="<?php echo esc_attr(get_option('gdpr_audit_retention_days', 365)); ?>"
                               min="30" 
                               class="small-text">
                        <?php _e('days', 'wp-gdpr-framework'); ?>
                        <p class="description">
                            <?php _e('Number of days to keep audit log entries before deletion.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_enable_scheduled_reports">
                            <?php _e('Enable Scheduled Reports', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="checkbox" 
                               id="gdpr_enable_scheduled_reports"
                               name="gdpr_enable_scheduled_reports" 
                               value="1"
                               <?php checked(get_option('gdpr_enable_scheduled_reports', 0), 1); ?>>
                        <p class="description">
                            <?php _e('Enable automated generation of GDPR compliance reports.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_report_schedule">
                            <?php _e('Report Schedule', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <select name="gdpr_report_schedule" id="gdpr_report_schedule">
                            <option value="weekly" <?php selected(get_option('gdpr_report_schedule', 'monthly'), 'weekly'); ?>><?php _e('Weekly', 'wp-gdpr-framework'); ?></option>
                            <option value="monthly" <?php selected(get_option('gdpr_report_schedule', 'monthly'), 'monthly'); ?>><?php _e('Monthly', 'wp-gdpr-framework'); ?></option>
                            <option value="quarterly" <?php selected(get_option('gdpr_report_schedule', 'monthly'), 'quarterly'); ?>><?php _e('Quarterly', 'wp-gdpr-framework'); ?></option>
                        </select>
                        <p class="description">
                            <?php _e('How often to generate GDPR compliance reports.', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="gdpr_report_email">
                            <?php _e('Report Email Recipients', 'wp-gdpr-framework'); ?>
                        </label>
                    </th>
                    <td>
                        <input type="text" 
                               id="gdpr_report_email"
                               name="gdpr_report_email" 
                               value="<?php echo esc_attr(get_option('gdpr_report_email', get_option('admin_email'))); ?>"
                               class="regular-text">
                        <p class="description">
                            <?php _e('Email addresses to receive scheduled reports (comma-separated).', 'wp-gdpr-framework'); ?>
                        </p>
                    </td>
                </tr>
            </table>
            
            <h3><?php _e('Generate Compliance Reports', 'wp-gdpr-framework'); ?></h3>
            
            <table class="widefat">
                <thead>
                    <tr>
                        <th><?php _e('Report Type', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Description', 'wp-gdpr-framework'); ?></th>
                        <th><?php _e('Actions', 'wp-gdpr-framework'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><?php _e('Consent History', 'wp-gdpr-framework'); ?></td>
                        <td><?php _e('Generate a report of all consent activities.', 'wp-gdpr-framework'); ?></td>
                        <td>
                            <a href="<?php echo wp_nonce_url(
                                add_query_arg([
                                    'action' => 'gdpr_generate_report',
                                    'report_type' => 'consent'
                                ], admin_url('admin-post.php')),
                                'gdpr_generate_report'
                            ); ?>" class="button">
                                <?php _e('Generate', 'wp-gdpr-framework'); ?>
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <td><?php _e('Data Processing Log', 'wp-gdpr-framework'); ?></td>
                        <td><?php _e('Generate a report of all data processing activities.', 'wp-gdpr-framework'); ?></td>
                        <td>
                            <a href="<?php echo wp_nonce_url(
                                add_query_arg([
                                    'action' => 'gdpr_generate_report',
                                    'report_type' => 'processing'
                                ], admin_url('admin-post.php')),
                                'gdpr_generate_report'
                            ); ?>" class="button">
                                <?php _e('Generate', 'wp-gdpr-framework'); ?>
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <td><?php _e('Security Compliance', 'wp-gdpr-framework'); ?></td>
                        <td><?php _e('Generate a report of security settings and encryption logs.', 'wp-gdpr-framework'); ?></td>
                        <td>
                            <a href="<?php echo wp_nonce_url(
                                add_query_arg([
                                    'action' => 'gdpr_generate_report',
                                    'report_type' => 'security'
                                ], admin_url('admin-post.php')),
                                'gdpr_generate_report'
                            ); ?>" class="button">
                                <?php _e('Generate', 'wp-gdpr-framework'); ?>
                            </a>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <?php submit_button(); ?>
    </form>
</div>

<!-- Template for new consent type -->
<script type="text/template" id="consent-type-template">
    <div class="consent-type-item">
        <div class="consent-type-header">
            <input type="text"
                   name="gdpr_consent_types[{{id}}][label]"
                   class="regular-text"
                   placeholder="<?php _e('Consent Type Label', 'wp-gdpr-framework'); ?>"
                   required>
            
            <label class="required-checkbox">
                <input type="checkbox"
                       name="gdpr_consent_types[{{id}}][required]"
                       value="1">
                <?php _e('Required', 'wp-gdpr-framework'); ?>
            </label>
            
            <button type="button" class="button remove-consent-type">
                <?php _e('Remove', 'wp-gdpr-framework'); ?>
            </button>
        </div>
        
        <textarea name="gdpr_consent_types[{{id}}][description]"
                  class="large-text"
                  placeholder="<?php _e('Description', 'wp-gdpr-framework'); ?>"
                  required></textarea>
    </div>
</script>
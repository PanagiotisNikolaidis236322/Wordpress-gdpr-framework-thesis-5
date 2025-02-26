<?php if (!defined('ABSPATH')) exit; ?>

<div class="gdpr-consent-form">
    <form id="gdprConsentForm" method="post">
        <?php wp_nonce_field('gdpr_nonce', 'gdpr_nonce'); ?>
        
        <div class="gdpr-consent-options">
            <?php foreach ($consent_types as $type => $data): ?>
                <div class="consent-option <?php echo (!empty($data['required'])) ? 'required-consent' : ''; ?>">
                    <label class="consent-label">
                    <input type="checkbox" 
                        name="consents[<?php echo esc_attr($type); ?>]"
                        data-consent-type="<?php echo esc_attr($type); ?>"
                        value="1"
                        <?php checked($current_consents[$type] ?? false); ?>
                        <?php echo (!empty($data['required'])) ? 'required disabled checked' : ''; ?>>
                        <span class="consent-text">
                            <?php echo esc_html($data['label']); ?>
                            <?php if (!empty($data['required'])): ?>
                                <span class="required">*</span>
                            <?php endif; ?>
                        </span>
                    </label>
                    <p class="description"><?php echo esc_html($data['description']); ?></p>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="gdpr-consent-buttons">
            <?php if (!empty($show_reset)): ?>
                <button type="button" class="button reset-consent">
                    <?php _e('Reset Preferences', 'wp-gdpr-framework'); ?>
                </button>
            <?php endif; ?>
            <button type="submit" class="button button-primary update-consent">
                <?php _e('Update Privacy Settings', 'wp-gdpr-framework'); ?>
            </button>
        </div>

        <div class="gdpr-consent-notice" style="display:none;"></div>
    </form>
</div>
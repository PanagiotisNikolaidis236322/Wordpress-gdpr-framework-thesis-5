jQuery(document).ready(function($) {
    'use strict';

    function debug(message, data = null) {
        if (console && console.log) {
            console.log('GDPR Framework:', message);
            if (data) {
                console.log(data);
            }
        }
    }

    class ConsentForm {
        constructor(element) {
            debug('Initializing consent form');
            this.form = $(element);
            this.notice = this.form.find('.gdpr-consent-notice');
            this.submitButton = this.form.find('button[type="submit"]');
            this.resetButton = this.form.find('.reset-consent');
            this.checkboxes = this.form.find('input[type="checkbox"]');
            
            this.bindEvents();
        }

        bindEvents() {
            this.form.on('submit', (e) => this.handleSubmit(e));
            this.resetButton.on('click', () => this.handleReset());
            this.checkboxes.on('change', (e) => this.handleCheckboxChange(e));
        }

        async handleSubmit(e) {
            e.preventDefault();
            debug('Form submitted');

            // Collect all consent values at once
            const consents = {};
            this.checkboxes.each((_, checkbox) => {
                const $checkbox = $(checkbox);
                const type = $checkbox.data('consent-type');
                if (type) {
                    consents[type] = $checkbox.is(':checked') ? 1 : 0;
                }
            });

            debug('Collected consents', consents);
            this.setLoading(true);
            this.clearNotice();

            try {
                const response = await $.ajax({
                    url: gdprConsentForm.ajaxUrl,
                    method: 'POST',
                    data: {
                        action: 'update_user_consent',
                        consents: consents,
                        gdpr_nonce: gdprConsentForm.nonce
                    }
                });

                debug('Server response', response);

                if (response.success) {
                    this.showNotice('success', gdprConsentForm.i18n.success);
                    this.form.trigger('consent:updated');
                } else {
                    throw new Error(response.data.message || gdprConsentForm.i18n.error);
                }
            } catch (error) {
                debug('Error processing consents', error);
                this.showNotice('error', error.message || gdprConsentForm.i18n.error);
            } finally {
                this.setLoading(false);
            }
        }

        handleReset() {
            if (!confirm(gdprConsentForm.i18n.confirmReset)) {
                return;
            }

            debug('Resetting consent form');
            this.checkboxes.each((_, checkbox) => {
                const $checkbox = $(checkbox);
                if (!$checkbox.prop('disabled')) {
                    $checkbox.prop('checked', false);
                }
            });

            // Automatically submit form after reset
            this.form.submit();
        }

        handleCheckboxChange(e) {
            const $checkbox = $(e.target);
            const type = $checkbox.data('consent-type');
            
            debug(`Checkbox changed: ${type} - ${$checkbox.is(':checked')}`);
            
            // Prevent unchecking required consents
            if ($checkbox.prop('disabled') && !$checkbox.is(':checked')) {
                $checkbox.prop('checked', true);
                return false;
            }
        }

        setLoading(loading) {
            debug('Setting loading state:', loading);
            this.submitButton
                .prop('disabled', loading)
                .text(loading ? gdprConsentForm.i18n.updating : gdprConsentForm.i18n.update);
            this.checkboxes.not('[disabled]').prop('disabled', loading);
            this.resetButton.prop('disabled', loading);
        }

        showNotice(type, message) {
            debug('Showing notice:', { type, message });
            this.notice
                .removeClass('gdpr-success gdpr-error')
                .addClass(`gdpr-${type}`)
                .html(message)
                .fadeIn();

            if (type === 'success') {
                setTimeout(() => this.clearNotice(), 5000);
            }
        }

        clearNotice() {
            this.notice.removeClass('gdpr-success gdpr-error').fadeOut();
        }
    }

    // Initialize all consent forms
    debug('Looking for consent forms');
    const forms = $('.gdpr-consent-form');
    debug(`Found ${forms.length} consent forms`);
    
    forms.each((_, form) => new ConsentForm(form));
});
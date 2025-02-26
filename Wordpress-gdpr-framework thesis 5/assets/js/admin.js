jQuery(document).ready(function($) {
    'use strict';

    // Tab switching initialization
    function initializeTabs() {
        console.log('Initializing GDPR Framework tabs...');
        
        // Ensure first tab is active on page load if no tab is already active
        $('.tab-content').hide();
        
        // Check if localStorage has a saved tab
        if (typeof(localStorage) !== 'undefined') {
            var lastTab = localStorage.getItem('gdprActiveTab');
            if (lastTab && $(lastTab).length) {
                $('.nav-tab[href="' + lastTab + '"]').addClass('nav-tab-active');
                $(lastTab).show();
            } else {
                $('.nav-tab:first').addClass('nav-tab-active');
                $('.tab-content:first').show();
            }
        } else {
            $('.nav-tab:first').addClass('nav-tab-active');
            $('.tab-content:first').show();
        }
    
        // Fix the click handler - use jQuery's on method
        $(document).on('click', '.nav-tab', function(e) {
            e.preventDefault();
            
            var targetId = $(this).attr('href');
            console.log('Tab clicked:', targetId);
            
            // Update active states
            $('.nav-tab').removeClass('nav-tab-active');
            $(this).addClass('nav-tab-active');
            
            // Hide all tab content and show the target tab
            $('.tab-content').hide();
            $(targetId).show();
            
            // Store active tab in localStorage if available
            if (typeof(localStorage) !== 'undefined') {
                localStorage.setItem('gdprActiveTab', targetId);
            }
        });
    }

    // Consent type management
    function initializeConsentTypes() {
        var consentTypeCount = $('#consent-types .consent-type-item').length;
        
        // Add new consent type
        $('#add-consent-type').on('click', function() {
            var template = $('#consent-type-template').html();
            template = template.replace(/{{id}}/g, consentTypeCount++);
            $('#consent-types').append(template);
        });

        // Remove consent type
        $(document).on('click', '.remove-consent-type', function() {
            if (confirm(gdprFrameworkAdmin.i18n.confirmDelete)) {
                $(this).closest('.consent-type-item').remove();
            }
        });
    }

    // Data request processing
    function initializeRequestProcessing() {
        $('.process-request').on('click', function() {
            const $button = $(this);
            const requestId = $button.data('id');
            const requestType = $button.data('type');
            const nonce = $button.data('nonce');

            if (!confirm(
                requestType === 'export' 
                    ? gdprFrameworkAdmin.i18n.confirmExport
                    : gdprFrameworkAdmin.i18n.confirmErasure
            )) {
                return;
            }

            $button.prop('disabled', true)
                   .addClass('processing')
                   .text(gdprFrameworkAdmin.i18n.processing);

            $.ajax({
                url: gdprFrameworkAdmin.ajaxUrl,
                method: 'POST',
                data: {
                    action: 'gdpr_process_request',
                    request_id: requestId,
                    request_type: requestType,
                    nonce: nonce
                },
                success: function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        alert(response.data.message || gdprFrameworkAdmin.i18n.error);
                        $button.prop('disabled', false)
                               .removeClass('processing')
                               .text(gdprFrameworkAdmin.i18n.processRequest);
                    }
                },
                error: function() {
                    alert(gdprFrameworkAdmin.i18n.error);
                    $button.prop('disabled', false)
                           .removeClass('processing')
                           .text(gdprFrameworkAdmin.i18n.processRequest);
                }
            });
        });
    }

    // Key rotation handling
    function initializeKeyRotation() {
        $('#gdpr-rotate-key').on('click', function() {
            if (!confirm(gdprFrameworkAdmin.i18n.confirmRotation)) {
                return;
            }

            var $button = $(this);
            $button.prop('disabled', true)
                   .text(gdprFrameworkAdmin.i18n.rotating);

            $.ajax({
                url: gdprFrameworkAdmin.ajaxUrl,
                method: 'POST',
                data: {
                    action: 'gdpr_rotate_key',
                    nonce: gdprFrameworkAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        alert(gdprFrameworkAdmin.i18n.rotateSuccess);
                        location.reload();
                    } else {
                        alert(response.data.message || gdprFrameworkAdmin.i18n.error);
                        $button.prop('disabled', false)
                               .text(gdprFrameworkAdmin.i18n.rotateKey);
                    }
                },
                error: function() {
                    alert(gdprFrameworkAdmin.i18n.error);
                    $button.prop('disabled', false)
                           .text(gdprFrameworkAdmin.i18n.rotateKey);
                }
            });
        });
    }

    // Manual cleanup handling
    function initializeManualCleanup() {
        $('#gdpr-manual-cleanup').on('click', function() {
            var $button = $(this);
            $button.prop('disabled', true)
                   .text(gdprFrameworkAdmin.i18n.cleaning);

            $.ajax({
                url: gdprFrameworkAdmin.ajaxUrl,
                method: 'POST',
                data: {
                    action: 'gdpr_manual_cleanup',
                    nonce: $(this).data('nonce')
                },
                success: function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        alert(gdprFrameworkAdmin.i18n.error);
                        $button.prop('disabled', false)
                               .text(gdprFrameworkAdmin.i18n.cleanup);
                    }
                },
                error: function() {
                    alert(gdprFrameworkAdmin.i18n.error);
                    $button.prop('disabled', false)
                           .text(gdprFrameworkAdmin.i18n.cleanup);
                }
            });
        });
    }

    // Report generation handling
    function initializeReportGeneration() {
        $('.generate-report-button').on('click', function() {
            var $button = $(this);
            var reportType = $button.data('report-type');
            
            $button.prop('disabled', true)
                   .text(gdprFrameworkAdmin.i18n.generating);
                   
            $.ajax({
                url: gdprFrameworkAdmin.ajaxUrl,
                method: 'POST',
                data: {
                    action: 'gdpr_generate_report',
                    report_type: reportType,
                    nonce: gdprFrameworkAdmin.nonce
                },
                success: function(response) {
                    if (response.success && response.data.download_url) {
                        // Open report in new window
                        window.open(response.data.download_url, '_blank');
                    } else {
                        alert(response.data.message || gdprFrameworkAdmin.i18n.error);
                    }
                    $button.prop('disabled', false)
                           .text(gdprFrameworkAdmin.i18n.generate);
                },
                error: function() {
                    alert(gdprFrameworkAdmin.i18n.error);
                    $button.prop('disabled', false)
                           .text(gdprFrameworkAdmin.i18n.generate);
                }
            });
        });
    }

    // Enforcement mode handling
    function initializeEnforcementMode() {
        $('input[name="gdpr_enforcement_mode"]').on('change', function() {
            var mode = $(this).val();
            
            if (mode === 'advanced') {
                $('.advanced-setting').fadeIn();
            } else {
                $('.advanced-setting').fadeOut();
            }
        });
        
        // Trigger on page load
        $('input[name="gdpr_enforcement_mode"]:checked').trigger('change');
    }

    

    // Toggle dependent fields
    function initializeFieldToggling() {
        // Toggle scheduled reports fields based on checkbox
        $('#gdpr_enable_scheduled_reports').on('change', function() {
            var enabled = $(this).is(':checked');
            $('#gdpr_report_schedule, #gdpr_report_email').closest('tr').toggle(enabled);
        }).trigger('change');
        
        // Toggle automatic key rotation fields
        $('#gdpr_enable_encryption').on('change', function() {
            var enabled = $(this).is(':checked');
            $('#gdpr-rotate-key').closest('tr').toggle(enabled);
            $('#gdpr_auto_key_rotation').closest('tr').toggle(enabled);
        }).trigger('change');
    }

    // Initialize all functionality
    function initialize() {
        console.log('GDPR Framework admin script initializing...');
        initializeTabs();
        initializeConsentTypes();
        initializeRequestProcessing();
        initializeKeyRotation();
        initializeManualCleanup();
        initializeReportGeneration();
        initializeEnforcementMode();
        initializeFieldToggling();
    }

    // Run initialization
    initialize();
});

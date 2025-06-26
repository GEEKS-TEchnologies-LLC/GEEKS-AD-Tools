/**
 * Flash Messages Auto-Dismiss Script
 * 
 * This script automatically dismisses Bootstrap alert messages after a configurable timeout.
 * Features:
 * - Auto-dismiss after configurable timeout (default: 3 minutes)
 * - Visual countdown timer (configurable via admin settings)
 * - Manual dismissal support
 * - Memory leak prevention
 * - Error handling
 * 
 * Configuration:
 * - Settings are loaded from server branding configuration
 * - flash_countdown: Whether to show countdown timer (default: false)
 * - flash_timeout: Time in seconds before auto-dismiss (default: 180)
 * 
 * Usage:
 * Include this script after Bootstrap JS in any template that has flash messages.
 * Flash messages should have the class 'alert' and optionally 'alert-message' span for countdown.
 */

// Auto-dismiss flash messages with visual countdown
document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.alert');
    if (flashMessages.length === 0) return;
    
    // Load configuration from server
    loadFlashConfig().then(config => {
        flashMessages.forEach(function(alert) {
            if (!alert || !alert.parentNode) return;
            
            let countdownInterval = null;
            const timeoutDuration = (config.flash_timeout || 180) * 1000; // Convert to milliseconds
            
            // Add countdown indicator if enabled
            if (config.flash_countdown) {
                const countdownSpan = document.createElement('span');
                countdownSpan.className = 'ms-2 text-muted';
                countdownSpan.style.fontSize = '0.875rem';
                countdownSpan.innerHTML = '<i class="fas fa-clock me-1"></i>Auto-dismiss in <span class="countdown-timer">' + formatTime(config.flash_timeout || 180) + '</span>';
                
                // Insert the countdown after the message text
                const messageText = alert.querySelector('.alert-message') || alert;
                if (messageText) {
                    messageText.appendChild(countdownSpan);
                    
                    // Start countdown timer
                    let timeLeft = config.flash_timeout || 180; // Time in seconds
                    const countdownElement = countdownSpan.querySelector('.countdown-timer');
                    
                    countdownInterval = setInterval(function() {
                        timeLeft--;
                        countdownElement.textContent = formatTime(timeLeft);
                        
                        if (timeLeft <= 0) {
                            clearInterval(countdownInterval);
                        }
                    }, 1000);
                }
            }
            
            // Auto-dismiss after timeout
            const dismissTimeout = setTimeout(function() {
                if (alert && alert.parentNode) {
                    if (countdownInterval) {
                        clearInterval(countdownInterval);
                    }
                    try {
                        const bsAlert = new bootstrap.Alert(alert);
                        bsAlert.close();
                    } catch (e) {
                        // Fallback: remove the alert manually
                        alert.remove();
                    }
                }
            }, timeoutDuration);
            
            // Clean up when manually dismissed
            alert.addEventListener('closed.bs.alert', function() {
                if (countdownInterval) {
                    clearInterval(countdownInterval);
                }
                clearTimeout(dismissTimeout);
            });
            
            // Clean up when alert is removed from DOM
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.type === 'childList' && !document.contains(alert)) {
                        if (countdownInterval) {
                            clearInterval(countdownInterval);
                        }
                        clearTimeout(dismissTimeout);
                        observer.disconnect();
                    }
                });
            });
            
            observer.observe(document.body, {
                childList: true,
                subtree: true
            });
        });
    }).catch(error => {
        console.warn('Failed to load flash configuration, using defaults:', error);
        // Fallback to default behavior (no countdown, 3 minute timeout)
        flashMessages.forEach(function(alert) {
            if (!alert || !alert.parentNode) return;
            
            setTimeout(function() {
                if (alert && alert.parentNode) {
                    try {
                        const bsAlert = new bootstrap.Alert(alert);
                        bsAlert.close();
                    } catch (e) {
                        alert.remove();
                    }
                }
            }, 180000); // 3 minutes default
        });
    });
});

// Load flash configuration from server
async function loadFlashConfig() {
    try {
        const response = await fetch('/admin/get_flash_config');
        if (!response.ok) {
            throw new Error('Failed to load configuration');
        }
        const data = await response.json();
        return {
            flash_countdown: data.flash_countdown || false,
            flash_timeout: data.flash_timeout || 180,
            debug_mode: data.debug_mode || false
        };
    } catch (error) {
        console.warn('Error loading flash configuration:', error);
        // Return default configuration
        return {
            flash_countdown: false,
            flash_timeout: 180,
            debug_mode: false
        };
    }
}

// Format time as MM:SS
function formatTime(seconds) {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
} 
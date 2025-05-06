<?php
/**
 * formProtectionHook
 *
 * A FormIt hook for MODX that provides enhanced spam protection through
 * content filtering, timed submissions, and email validation.
 *
 * IMPORTANT: Requires the generateTimeTokenHook to be used as a preHook
 * and a hidden input field in the form for the time token.
 *
 * @author Jay Gilmore <jay@modx.com>
 * @package formit
 * @subpackage hooks
 *
 * PROPERTIES:
 * -------------------
 * spamEmailField          - Field name for email address (default: email)
 * spamWordPatterns        - Comma-separated list of spam words/patterns to check for
 * spamEmailPatterns       - Comma-separated list of spam email patterns to reject
 * spamTimeField           - Field name for time token (default: form_time_token)
 * spamTimeThreshold       - Minimum seconds before form submission is allowed (default: 7)
 * spamContentErrorMessage - Error message for spam content detection
 * spamEmailErrorMessage   - Error message for spam email detection
 * timeTokenErrorMessage   - Error message for invalid time token
 * timeThresholdErrorMessage - Error message for form submitted too fast
 *
 * USAGE:
 * 1. Add the generateTimeTokenHook as a preHook:
 * [[!FormIt?
 *   &preHooks=`generateTimeTokenHook`
 *   &hooks=`formProtectionHook,email`
 *   &spamTimeThreshold=`5`
 *   ...
 * ]]
 *
 * 2. Add this hidden input to your form:
 * <input type="hidden" name="form_time_token" id="form_time_token" value="[[!+fi.form_time_token]]">
 */

// Get form values 
$formFields = $hook->getValues();

// Get email field
$emailField = $modx->getOption('spamEmailField', $scriptProperties, 'email');

// Load spam patterns
$spamWords = $modx->getOption('spamWordPatterns', $scriptProperties, 
    'viagra,porn,sex,shit,fuck,bit.ly,youtube,free,optimization,CRM,bitcoin,crypto,ericjones');
$spamWordPatterns = array_map('trim', explode(',', $spamWords));

$spamEmails = $modx->getOption('spamEmailPatterns', $scriptProperties, 
    'order-fulfillment.net,bestlocaldata.com,.ru');
$spamEmailPatterns = array_map('trim', explode(',', $spamEmails));

// Configurable error messages
$spamContentErrorMessage = $modx->getOption('spamContentErrorMessage', $scriptProperties, 'Input picked up as spam.');
$spamEmailErrorMessage = $modx->getOption('spamEmailErrorMessage', $scriptProperties, 'Email picked up as spam.');
$timeTokenErrorMessage = $modx->getOption('timeTokenErrorMessage', $scriptProperties, 'Invalid time token.');
$timeThresholdErrorMessage = $modx->getOption('timeThresholdErrorMessage', $scriptProperties, 'Form submitted too fast. Please wait a moment.');

// Include rateLimiter
$path = $modx->getOption('formprotection.core_path', null, $modx->getOption('core_path') . 'components/formprotection/') . 'includes/';
require_once($path . 'rateLimiter.php');

// Rate limiting check
if (isRateLimited('formProtection', 30)) {
    $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Rate limit exceeded: Too many submissions.");
    $hook->addError('rate_limit', 'Rate limit exceeded. Too many submissions.');
    return false;
}
// Spam content check for all text fields
foreach ($formFields as $fieldName => $fieldValue) {
    // Skip non-text fields (e.g., hidden fields, checkboxes, etc.)
    if (is_array($fieldValue) || in_array($fieldName, [$emailField, 'form_time_token'])) {
        continue;
    }

    if (empty($fieldValue)) {
        continue;
    }

    foreach ($spamWordPatterns as $spam) {
        if (!empty($spam) && stripos($fieldValue, $spam) !== false) {
            $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] SPAM DETECTED in field '$fieldName' with pattern '$spam'");
            $hook->addError($fieldName, $spamContentErrorMessage);
        }
    }
}

// Email pattern spam check
if (isset($formFields[$emailField])) {
    $email = $formFields[$emailField];

    foreach ($spamEmailPatterns as $spam) {
        if (!empty($spam) && stripos($email, $spam) !== false) {
            $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Spam email detected with pattern '$spam'");
            $hook->addError($emailField, $spamEmailErrorMessage);
        }
    }
}

// Time token validation (only if there are no existing form errors)
if (empty($hook->getErrors())) {
    $timeField = $modx->getOption('spamTimeField', $scriptProperties, 'form_time_token');
    $secretKey = $modx->getOption('formit.spam_time_secret', null, 'changeme');
    $threshold = (int)$modx->getOption('spamTimeThreshold', $scriptProperties, 7);

    $token = $formFields[$timeField] ?? '';

    if (!empty($token) && strpos($token, ':') !== false) {
        list($timestamp, $hash) = explode(':', $token);

        $expectedHash = hash_hmac('sha256', $timestamp, $secretKey);

        if (!hash_equals($expectedHash, $hash)) {
            $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Time token hash validation failed");
            $hook->addError($timeField, $timeTokenErrorMessage);
        } else {
            $elapsed = time() - (int)$timestamp;

            if ($elapsed < $threshold) {
                $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Form submitted too quickly ($elapsed seconds < $threshold seconds threshold)");
                $hook->addError($timeField, $timeThresholdErrorMessage);
            }
        }
    } else {
        $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Invalid time token format");
        $hook->addError($timeField, $timeTokenErrorMessage);
    }
}

// Optionally clear the token from session after successful submission
$sessionKey = $modx->getOption('spamTimeSessionKey', $scriptProperties, 'form_time_token');
if (session_status() === PHP_SESSION_NONE) {
    @session_start();
}
if (session_status() === PHP_SESSION_ACTIVE && isset($_SESSION[$sessionKey])) {
    unset($_SESSION[$sessionKey]);
}

// Return true only if there are no errors
return empty($hook->getErrors());
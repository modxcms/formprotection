<?php
/**
 * formProtectionHook
 *
 * A FormIt hook for MODX that adds extra spam protection via:
 * - Spam word and email filtering
 * - Submission timing check using a time token
 * - Optional rate limiting
 * - Optional redirection for suspected spammers
 *
 * IMPORTANT:
 * - This hook requires the `generateTimeTokenHook` to be used as a preHook.
 * - You must include a hidden time token field in your form.
 * 
 * @author Jay Gilmore <jay@modx.com>
 * @package formprotection
 * @subpackage hooks
 * 
 * PROPERTIES:
 * -------------------
 * spamEmailField            - Name of the email field to check (default: email)
 * spamWordPatterns          - Comma-separated list of spam keywords (default includes common spam terms)
 * spamEmailPatterns         - Comma-separated list of email domains or patterns to reject
 * spamTimeField             - Name of the hidden time token field (default: form_time_token)
 * spamTimeThreshold         - Minimum seconds before the form can be submitted (default: 7)
 * formId                    - Optional form ID for unique rate limiting per form
 *
 * spamContentErrorMessage   - Error message shown when spammy content is found
 * spamEmailErrorMessage     - Error message shown for spammy email addresses
 * timeTokenErrorMessage     - Error message shown for invalid or missing time token
 * timeThresholdErrorMessage - Error message shown if the form was submitted too quickly
 * rateLimitErrorMessage     - Error shown if submission exceeds rate limit
 * rateLimitMaxSubmissionsErrorMessage - Error shown if the total submission limit is exceeded
 *
 * rateLimit                 - Enable or disable rate limiting (default: true)
 * rateLimitSeconds          - Seconds to wait before allowing another submission (default: 30)
 * rateLimitActionKey        - Unique action key for rate limiting (default: formProtection)
 * rateLimitMaxSubmissions   - Maximum number of submissions allowed within the timeframe (default: 5)
 * rateLimitSubmissionInterval - Timeframe for counting submissions in seconds (default: 86400, i.e., 1 day)
 *
 * spamRedirectResourceId    - Resource ID of the page to redirect suspected spammers to. 
 *                             If not set or invalid, no redirection occurs. 
 *                             The "submitted too fast" error does not trigger a redirect.
 *
 * spamTimeSessionKey        - Session key used for clearing the time token (default: form_time_token)
 *
 * USAGE:
 * -------------------
 * [[!FormIt?
 *   &preHooks=`generateTimeTokenHook`
 *   &hooks=`formProtectionHook,email`
 *   &spamTimeThreshold=`5`
 *   &rateLimit=`1`
 *   &spamRedirectResourceId=`123`
 *   ...
 * ]]
 *
 *
 * Inside your form:
 * <input type="hidden" name="form_time_token" value="[[!+fi.form_time_token]]">
 * 
 * To display error messages for Time Token and Rate Limit 
 * add the following to the top of your form:
 * [[!+fi.error.form_time_token]]
 * [[!+fi.error.rate_limit]]
 * 
 */


// Get form values 
/** @var modX $modx */
$formFields = $hook->getValues();
$errors = array();

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
$spamContentErrorMessage = $modx->getOption('spamContentErrorMessage', $scriptProperties, 'Your input contains words that are not allowed. Please revise your text and try again.');
$spamEmailErrorMessage = $modx->getOption('spamEmailErrorMessage', $scriptProperties, 'The email address you entered appears invalid or flagged. Please use a valid email address.');
$timeTokenErrorMessage = $modx->getOption('timeTokenErrorMessage', $scriptProperties, 'There was an issue with your session. Please refresh the page and try submitting the form again.');
$timeThresholdErrorMessage = $modx->getOption('timeThresholdErrorMessage', $scriptProperties, 'You submitted the form unusually quickly. Please wait a few seconds and try again.');
$rateLimitErrorMessage = $modx->getOption('rateLimitErrorMessage', $scriptProperties, 'You just submitted this form successfully. Please wait a while before submitting again.');
$rateLimitMaxSubmissionsErrorMessage = $modx->getOption(
    'rateLimitMaxSubmissionsErrorMessage',
    $scriptProperties,
    'You have reached the maximum number of submissions allowed. Please try again later.'
);

// Check if rate limiting is enabled
$enableRateLimit = (bool)$modx->getOption('rateLimit', $scriptProperties, true);

// Apply rate limiting if there are no other errors
if ($enableRateLimit && empty($hook->getErrors())) {
    // Include rateLimiter
    $path = $modx->getOption('formprotection.core_path', null, $modx->getOption('core_path') . 'components/formprotection/') . 'includes/';
    
    // Check if file exists before requiring
    if (file_exists($path . 'rateLimiter.php')) {
        require_once($path . 'rateLimiter.php');
        
        // Rate limiting seconds
        $rateLimitSeconds = (int)$modx->getOption('rateLimitSeconds', $scriptProperties, 30);
        
        // Allow custom action key per form
        $rateLimitActionKey = $modx->getOption('rateLimitActionKey', $scriptProperties, 'formProtection');
        
        // Optionally append form ID to make rate limiting unique per form
        $formId = $modx->getOption('formId', $scriptProperties, '');
        if (!empty($formId)) {
            $rateLimitActionKey .= "_{$formId}";
        }
        
        // Retrieve the cookie name from script properties
        $cookieName = $modx->getOption('rateLimitCookieName', $scriptProperties, 'submission');

        // Retrieve the maximum submissions and submission interval
        $rateLimitMaxSubmissions = (int)$modx->getOption('rateLimitMaxSubmissions', $scriptProperties, 5);
        $rateLimitSubmissionInterval = (int)$modx->getOption('rateLimitSubmissionInterval', $scriptProperties, 86400);

        // Check if the IP + User-Agent + Cookie exceeds the submission limit
        if (function_exists('isRateLimited')) {
            $rateLimitResult = isRateLimited(
                $rateLimitActionKey,
                $rateLimitSeconds,
                $cookieName,
                $rateLimitMaxSubmissions,
                $rateLimitSubmissionInterval
            );

            if ($rateLimitResult === 1) {
                // Per-request delay triggered
                $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Rate limit exceeded: Per-request delay.");
                $hook->addError('rate_limit', $rateLimitErrorMessage); // Short timeframe error
                return false;
            } elseif ($rateLimitResult === 2) {
                // Max submissions per day triggered
                $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Rate limit exceeded: Max submissions per day.");
                $hook->addError('rate_limit', $rateLimitMaxSubmissionsErrorMessage); // Max submissions error
                return false;
            }
        }
    } else {
        $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] rateLimiter.php not found at: {$path}");
    }
}

// Spam content check for all text fields
foreach ($formFields as $fieldName => $fieldValue) {
    // Skip non-text fields (e.g., hidden fields, checkboxes, etc.)
    if (is_array($fieldValue) || in_array($fieldName, [$emailField, 'form_time_token'])) {
        continue;
    }

    // Skip empty fields
    if (empty($fieldValue)) {
        continue;
    }

    // Check for spam patterns
    $spamWordRegex = '/' . implode('|', array_map('preg_quote', $spamWordPatterns)) . '/i';
    if (preg_match($spamWordRegex, $fieldValue)) {
        $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] SPAM DETECTED in field '{$fieldName}'");
        $hook->addError($fieldName, $spamContentErrorMessage);
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

// Time token validation
$timeField = $modx->getOption('spamTimeField', $scriptProperties, 'form_time_token');
$secretKey = $modx->getOption('formit.spam_time_secret', null, 'changeme');
$threshold = (int)$modx->getOption('spamTimeThreshold', $scriptProperties, 7);

$token = isset($formFields[$timeField]) ? $formFields[$timeField] : '';

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
        } else {
            $modx->log(modX::LOG_LEVEL_INFO, "[FormProtection] Time token validation successful ($elapsed seconds elapsed)");
        }
    }
} else {
    $modx->log(modX::LOG_LEVEL_ERROR, "[FormProtection] Invalid time token format");
    $hook->addError($timeField, $timeTokenErrorMessage);
}
// Check for spam redirect resource ID
$spamRedirectResourceId = $modx->getOption('spamRedirectResourceId', $scriptProperties, null);

if (!empty($spamRedirectResourceId) && is_numeric($spamRedirectResourceId)) {
    // Get all errors
    $errors = $hook->getErrors();

    // Exclude the "submitted too fast" error from triggering the redirect
    if (isset($errors['form_time_token']) && $errors['form_time_token'] === $timeThresholdErrorMessage) {
        $modx->log(modX::LOG_LEVEL_INFO, "[FormProtection] Skipping redirect for 'submitted too fast' error.");
    } elseif (!empty($errors)) {
        // Redirect for all other errors
        $redirectUrl = $modx->makeURL((int)$spamRedirectResourceId, '', '', 'full');
        $modx->log(modX::LOG_LEVEL_INFO, "[FormProtection] Redirecting suspected spammer to resource ID {$spamRedirectResourceId}");
        header("Location: {$redirectUrl}");
        exit;
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
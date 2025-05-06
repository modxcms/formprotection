<?php
/**
 * generateTimeTokenHook
 *
 * A FormIt preHook for MODX that generates a time-based token for spam protection.
 * This hook generates a timestamped token which is then validated by the 
 * formProtectionHook to prevent bot submissions and form spam.
 *
 * @author Jay Gilmore <jay@modx.com>
 * @package formit
 * @subpackage hooks
 *
 * PROPERTIES:
 * -------------------
 * spamTimeSessionKey - (optional) The session key used to store the token. Defaults to 'form_time_token'.
 *
 * SYSTEM SETTINGS:
 * -------------------
 * formit.spam_time_secret - Secret key used for token generation (default: changeme)
 *
 * USAGE:
 * 1. Add this hook as a preHook in your FormIt call:
 * [[!FormIt?
 *   &preHooks=`generateTimeTokenHook`
 *   &hooks=`formProtectionHook,email`
 *   ...
 * ]]
 *
 * 2. Add this hidden input to your form:
 * <input type="hidden" name="form_time_token" id="form_time_token" value="[[!+fi.form_time_token]]">
 */
 
 $modx = $hook->modx;
 // Field name for form and placeholder
 $field = 'form_time_token';
 
 // Allow configurable session key
 $sessionKey = $modx->getOption('spamTimeSessionKey', $scriptProperties, 'form_time_token');
 
 // Start session if available
 if (session_status() === PHP_SESSION_NONE) {
     @session_start();
 }
 
 $token = '';
 
 // Try to reuse from session
 if (!empty($_SESSION[$sessionKey])) {
     $token = $_SESSION[$sessionKey];
 }
 // Or fallback to submitted POST value
 elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST[$field])) {
     $token = $_POST[$field];
 }
 // Otherwise generate a new token
 else {
     $secret = $modx->getOption('formit.spam_time_secret', null, 'changeme');
     $timestamp = time();
     $hash = hash_hmac('sha256', $timestamp, $secret);
     $token = $timestamp . ':' . $hash;
 }
 
 // Store in session (if enabled) and set as placeholder
 if (session_status() === PHP_SESSION_ACTIVE) {
     $_SESSION[$sessionKey] = $token;
 }
 
 $hook->setValue($field, $token);
 return true;
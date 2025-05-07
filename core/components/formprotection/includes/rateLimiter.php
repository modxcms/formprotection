<?php
/**
 * Rate Limiter for Form Protection
 * 
 * Provides rate limiting functionality to prevent form spam
 * Used with the formProtectionHook to limit the number of submissions.
 * 
 * @package formprotection
 * @author Jay Gilmore (jay@modx.com)
 * 
 */

/**
 * Check if a request is rate limited based on IP and action
 * 
 * @param string $actionKey A unique identifier for the action being rate limited
 * @param int $limitSeconds The number of seconds to enforce rate limiting
 * @return bool True if rate limited, false otherwise
 */
function isRateLimited($actionKey, $limitSeconds = 10) {
    // Get client IP address
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // Create a unique key based on the action and IP
    $key = md5($actionKey . '_' . $ip);
    
    // Set the file path in the temp directory
    $file = sys_get_temp_dir() . "/ratelimit_{$key}.tmp";
    
    // Get current timestamp
    $now = time();
    
    // Check if a record exists for this key
    if (file_exists($file)) {
        $last = (int)file_get_contents($file);
        
        // If the time elapsed is less than the limit, rate limit
        if (($now - $last) < $limitSeconds) {
            return true;
        }
    }
    
    // Store the current timestamp
    file_put_contents($file, $now);
    
    // Not rate limited
    return false;
}
<?php
/**
 * Rate Limiter for Form Protection
 * 
 * Provides rate limiting functionality to prevent form spam
 * Used with the formProtectionHook to limit the number of submissions.
 * 
 * @package formprotection
 */

/**
 * Check if a request is rate limited based on IP, User-Agent, and a cookie
 * 
 * @param string $actionKey A unique identifier for the action being rate limited
 * @param int $limitSeconds The number of seconds to enforce rate limiting
 * @param string $cookieName The name of the cookie used for rate limiting (default: 'submission')
 * @param int $maxSubmissions The maximum number of submissions allowed within the submission interval
 * @param int $submissionInterval The interval in seconds to count submissions (default: 86400 seconds)
 * @return int 2 if rate limited due to max submissions, 1 if rate limited due to per-request delay, 0 if not rate limited
 */
function isRateLimited($actionKey, $limitSeconds = 10, $cookieName = 'submission', $maxSubmissions = 5, $submissionInterval = 86400) {
    // Get client IP address and User-Agent
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    // Generate a unique cookie if it doesn't exist
    if (!isset($_COOKIE[$cookieName])) {
        $cookieValue = bin2hex(random_bytes(16)); // Generate a random token
        setcookie($cookieName, $cookieValue, time() + (86400 * 30), "/"); // 30-day expiration
    } else {
        $cookieValue = $_COOKIE[$cookieName];
    }

    // Create a unique key based on the action, IP, User-Agent, and cookie
    $key = hash('sha256', $actionKey . '_' . $ip . '_' . $userAgent . '_' . $cookieValue);

    // Set the file path in the temp directory
    $file = sys_get_temp_dir() . "/ratelimit_{$key}.tmp";

    // Get current timestamp
    $now = time();

    // Load submission timestamps from the file
    $timestamps = file_exists($file) ? json_decode(file_get_contents($file), true) : [];

    // Remove timestamps outside the submission interval
    $timestamps = array_filter($timestamps, function ($timestamp) use ($now, $submissionInterval) {
        return ($now - $timestamp) <= $submissionInterval;
    });

    // Check if the number of submissions exceeds the limit
    if (count($timestamps) >= $maxSubmissions) {
        error_log("[RateLimiter] Rate limited due to max submissions: " . count($timestamps));
        return 2; // Rate limited due to max submissions
    }

    // Enforce the per-request rate limit (e.g., 10 seconds between submissions)
    if (count($timestamps) > 1 && ($now - $timestamps[count($timestamps) - 2]) < $limitSeconds) {
        error_log("[RateLimiter] Rate limited due to per-request delay");
        return 1; // Rate limited due to per-request delay
    }

    // Add the current timestamp and save back to the file
    $timestamps[] = $now;
    file_put_contents($file, json_encode($timestamps));

    // Garbage collection: Remove old temp files and limit total file count
    $tempDir = sys_get_temp_dir();
    $files = glob($tempDir . '/ratelimit_*.tmp');
    $gcThreshold = 86400; // 1 day
    $maxFiles = 1000; // Maximum number of files allowed

    // Remove files older than the threshold
    foreach ($files as $tempFile) {
        if (filemtime($tempFile) < ($now - $gcThreshold)) {
            @unlink($tempFile); // Suppress errors if the file is already deleted
        }
    }

    // If the total number of files exceeds the limit, delete the oldest files
    if (count($files) > $maxFiles) {
        // Sort files by modification time (oldest first)
        usort($files, function ($a, $b) {
            return filemtime($a) - filemtime($b);
        });

        // Delete files exceeding the max limit
        foreach (array_slice($files, 0, count($files) - $maxFiles) as $tempFile) {
            @unlink($tempFile);
        }
    }

    // Not rate limited
    return 0;
}
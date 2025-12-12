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
 * Check if a request is rate limited based on IP and User-Agent (cookie supplemental)
 *
 * @param string $actionKey A unique identifier for the action being rate limited
 * @param int $limitSeconds The number of seconds to enforce rate limiting
 * @param string $cookieName The name of the cookie used for rate limiting (default: 'submission')
 * @param int $maxSubmissions The maximum number of submissions allowed within the submission interval
 * @param int $submissionInterval The interval in seconds to count submissions (default: 86400 seconds)
 * @return int 2 if rate limited due to max submissions, 1 if rate limited due to per-request delay, 0 if not rate limited
 */
function isRateLimited($actionKey, $limitSeconds = 10, $cookieName = 'submission', $maxSubmissions = 5, $submissionInterval = 86400) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    // Ensure supplemental cookie exists (not authoritative)
    if (!isset($_COOKIE[$cookieName])) {
        try {
            $cookieValue = bin2hex(random_bytes(16));
        } catch (Exception $e) {
            $cookieValue = bin2hex(openssl_random_pseudo_bytes(16));
        }
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        setcookie($cookieName, $cookieValue, time() + (86400 * 30), "/", "", $secure, true);
    } else {
        $cookieValue = $_COOKIE[$cookieName];
    }

    // Use server-side fingerprint (cookie removed from the key to prevent deletion bypass)
    $fingerprint = hash('sha256', $actionKey . '_' . $ip . '_' . $userAgent);
    $file = sys_get_temp_dir() . "/ratelimit_{$fingerprint}.tmp";
    $now = time();

    // Read existing timestamps (handle failures gracefully)
    $timestamps = [];
    if (file_exists($file)) {
        $contents = @file_get_contents($file);
        if ($contents !== false) {
            $decoded = json_decode($contents, true);
            if (is_array($decoded)) {
                $timestamps = $decoded;
            }
        }
    }

    // Keep only timestamps inside the submission interval
    $timestamps = array_filter($timestamps, function ($t) use ($now, $submissionInterval) {
        return is_numeric($t) && ($now - (int)$t) <= $submissionInterval;
    });
    $timestamps = array_values($timestamps);

    // Max submissions check
    if (count($timestamps) >= $maxSubmissions) {
        error_log("[RateLimiter] Rate limited due to max submissions: " . count($timestamps));
        return 2;
    }

    // Per-request delay: compare to the most recent previous submission (if any)
    if (count($timestamps) >= 1) {
        $last = (int)$timestamps[count($timestamps) - 1];
        if (($now - $last) < $limitSeconds) {
            error_log("[RateLimiter] Rate limited due to per-request delay");
            return 1;
        }
    }

    // Append current timestamp and write atomically with exclusive lock
    $timestamps[] = $now;
    @file_put_contents($file, json_encode($timestamps), LOCK_EX);

    // Garbage collection: remove old files and keep total file count reasonable
    $tempDir = sys_get_temp_dir();
    $files = glob($tempDir . '/ratelimit_*.tmp') ?: [];
    $gcThreshold = 86400 * 14; // 14 days
    $maxFiles = 1000;

    foreach ($files as $tempFile) {
        if (filemtime($tempFile) < ($now - $gcThreshold)) {
            @unlink($tempFile);
        }
    }

    // Refresh file list and trim if too many files exist
    $files = glob($tempDir . '/ratelimit_*.tmp') ?: [];
    if (count($files) > $maxFiles) {
        usort($files, function ($a, $b) {
            return filemtime($a) - filemtime($b);
        });
        foreach (array_slice($files, 0, count($files) - $maxFiles) as $tempFile) {
            @unlink($tempFile);
        }
    }

    return 0;
}

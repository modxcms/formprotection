<?php
function isRateLimited($actionKey, $limitSeconds = 10) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = md5($actionKey . '_' . $ip);
    $file = sys_get_temp_dir() . "/ratelimit_$key.tmp";

    $now = time();
    if (file_exists($file)) {
        $last = (int)file_get_contents($file);
        if (($now - $last) < $limitSeconds) {
            return true;
        }
    }
    file_put_contents($file, $now);
    return false;
}
?>
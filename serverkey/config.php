<?php
/**
 * PHUCVN 3105 - Hardened Core Configuration, Env Loader & Atomic Storage Layer
 */

if (session_status() === PHP_SESSION_NONE && PHP_SAPI !== 'cli') {
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') == 443);
    @session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'httponly' => true,
        'secure' => $isHttps,
        'samesite' => 'Strict',
    ]);
    @session_start();
}

date_default_timezone_set('Asia/Ho_Chi_Minh');

/**
 * Loads key=value pairs from .env outside web root first, without overriding OS environment.
 */
function loadServerEnv(): array {
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $vars = [];
    $candidates = array_filter([
        getenv('SERVERKEY_ENV_FILE') ?: null,
        dirname(__DIR__) . '/.env',
        dirname(__DIR__, 2) . '/.env',
        '/etc/phucvn3105/.env',
        __DIR__ . '/.env',
    ]);
    foreach ($candidates as $path) {
        if ($path && @is_file($path) && @is_readable($path)) {
            $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
                        continue;
                    }
                    [$k, $v] = explode('=', $line, 2);
                    $k = trim($k);
                    $v = trim($v);
                    if (strlen($v) >= 2 && (($v[0] === '"' && $v[-1] === '"') || ($v[0] === "'" && $v[-1] === "'"))) {
                        $v = substr($v, 1, -1);
                    }
                    $vars[$k] = $v;
                }
            }
            break;
        }
    }
    foreach ($_ENV as $k => $v) {
        if (is_string($v)) {
            $vars[$k] = $v;
        }
    }
    foreach ($vars as $k => $v) {
        $ev = getenv($k);
        if ($ev !== false) {
            $vars[$k] = $ev;
        }
    }
    $cache = $vars;
    return $cache;
}

function envValue(string $key, string $default = ''): string {
    $env = loadServerEnv();
    return isset($env[$key]) ? (string)$env[$key] : $default;
}

$configuredDataDir = envValue('SERVERKEY_DATA_DIR', '');
if ($configuredDataDir === '') {
    $outsideDefault = dirname(__DIR__) . '/phucvn_data';
    $configuredDataDir = @is_dir($outsideDefault) ? $outsideDefault : (__DIR__ . '/data');
}

define('DATA_DIR', rtrim($configuredDataDir, '/\\'));
define('USERS_FILE', DATA_DIR . '/users.json');
define('KEYS_FILE', DATA_DIR . '/keys.json');
define('SETTINGS_FILE', DATA_DIR . '/settings.json');
define('LOGS_FILE', DATA_DIR . '/logs.json');
define('MANIFESTS_FILE', DATA_DIR . '/build_manifests.json');
define('NONCES_FILE', DATA_DIR . '/api_nonces.json');
define('RATE_LIMITS_FILE', DATA_DIR . '/rate_limits.json');
define('LOGIN_LIMITS_FILE', DATA_DIR . '/login_limits.json');
define('BANNED_DEVICES_FILE', DATA_DIR . '/banned_devices.json');

if (!file_exists(DATA_DIR)) {
    @mkdir(DATA_DIR, 0750, true);
}

/**
 * Executes an atomic read-modify-write callback guarded by an exclusive flock.
 */
function withLockedJson(string $path, $default, callable $mutator) {
    $dir = dirname($path);
    if (!file_exists($dir)) {
        @mkdir($dir, 0750, true);
    }
    $lockPath = $dir . '/.' . basename($path) . '.lock';
    $lockFp = @fopen($lockPath, 'c+');
    if ($lockFp) {
        @flock($lockFp, LOCK_EX);
    }
    try {
        $current = $default;
        if (@is_file($path)) {
            $raw = @file_get_contents($path);
            if ($raw !== false && trim($raw) !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    $current = $decoded;
                }
            }
        }
        $dirty = false;
        $result = $mutator($current, $dirty);
        if ($dirty) {
            $tmp = $path . '.tmp.' . getmypid();
            $json = json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if (@file_put_contents($tmp, $json, LOCK_EX) !== false) {
                @chmod($tmp, 0640);
                @rename($tmp, $path);
            }
        }
        return $result;
    } finally {
        if ($lockFp) {
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
        }
    }
}

function readJsonFile($path, $default = []) {
    return withLockedJson((string)$path, $default, function ($cur) {
        return $cur;
    });
}

function writeJsonFile($path, $data) {
    return withLockedJson((string)$path, $data, function (&$cur, &$dirty) use ($data) {
        $cur = $data;
        $dirty = true;
        return true;
    });
}

function getSettings(): array {
    $defaults = [
        'app_name' => 'PHUCVN STUDIO',
        'admin_user' => envValue('ADMIN_USERNAME', 'phucvn_admin'),
        'admin_pass_hash' => envValue('ADMIN_PASS_HASH', ''),
        'allow_register' => false,
        'require_key' => true,
        'auto_activate' => true,
        'default_duration' => '30d',
        'bind_hwid' => true,
        'telegram_support' => 'https://t.me/phuciosvn',
        // Kill-Switch & Force Update policies
        'server_open' => true,
        'system_paused' => false,
        'server_closed_message' => 'Hệ thống máy chủ đang tạm đóng để bảo trì. Vui lòng quay lại sau.',
        'force_update' => false,
        'min_required_version' => '2.1.0',
        'latest_version' => '2.1.0',
        'download_url' => '',
        'update_message' => 'Phiên bản hiện tại đã cũ. Vui lòng cập nhật bản mới nhất để tiếp tục sử dụng.',
        'enforce_binary_hash' => false,
        'packages' => [],
    ];
    $current = readJsonFile(SETTINGS_FILE, []);
    $merged = array_merge($defaults, $current);
    if (!isset($merged['packages']) || !is_array($merged['packages'])) {
        $merged['packages'] = [];
    }
    return $merged;
}

function saveSettings($settings) {
    unset($settings['admin_pass']);
    return writeJsonFile(SETTINGS_FILE, $settings);
}

function resolvePackagePolicy(array $settings, string $packageId): array {
    $globalOpen = !empty($settings['server_open']) && empty($settings['system_paused']);
    $pkg = $settings['packages'][$packageId] ?? [];
    $pkgOpen = array_key_exists('server_open', $pkg) && $pkg['server_open'] !== null
        ? (bool)$pkg['server_open']
        : true;
    $serverOpen = $globalOpen && $pkgOpen;

    $closedMsg = !$globalOpen
        ? trim((string)($settings['server_closed_message'] ?: ($settings['notice_text'] ?? '')))
        : trim((string)($pkg['server_closed_message'] ?? $settings['server_closed_message'] ?? ''));
    if ($closedMsg === '') {
        $closedMsg = 'Hệ thống máy chủ đang tạm đóng để bảo trì. Vui lòng quay lại sau.';
    }

    return [
        'server_open' => $serverOpen,
        'closed_message' => $closedMsg,
        'force_update' => array_key_exists('force_update', $pkg) && $pkg['force_update'] !== null
            ? (bool)$pkg['force_update']
            : !empty($settings['force_update']),
        'min_required_version' => trim((string)($pkg['min_required_version'] ?? '')) !== ''
            ? trim((string)$pkg['min_required_version'])
            : (string)($settings['min_required_version'] ?? '2.1.0'),
        'latest_version' => trim((string)($pkg['latest_version'] ?? '')) !== ''
            ? trim((string)$pkg['latest_version'])
            : (string)($settings['latest_version'] ?? '2.1.0'),
        'download_url' => trim((string)($pkg['download_url'] ?? '')) !== ''
            ? trim((string)$pkg['download_url'])
            : (string)($settings['download_url'] ?? ''),
        'update_message' => trim((string)($pkg['update_message'] ?? '')) !== ''
            ? trim((string)$pkg['update_message'])
            : (string)($settings['update_message'] ?? 'Vui lòng cập nhật phiên bản mới nhất.'),
        'enforce_binary_hash' => array_key_exists('enforce_binary_hash', $pkg) && $pkg['enforce_binary_hash'] !== null
            ? (bool)$pkg['enforce_binary_hash']
            : !empty($settings['enforce_binary_hash']),
    ];
}

function calculateExpiryDate($duration, $baseDate = null) {
    $d = strtolower(trim((string)$duration));
    if ($d === 'permanent' || $d === '0' || $d === '') {
        return 'permanent';
    }
    $now = new DateTime();
    $dt = clone $now;
    if (!empty($baseDate) && $baseDate !== 'permanent') {
        try {
            $parsed = new DateTime($baseDate);
            if ($parsed > $now) {
                $dt = $parsed;
            }
        } catch (Exception $e) {}
    }
    switch ($d) {
        case '1h':
        case '1hour':
            $dt->modify('+1 hour');
            break;
        case '1d':
        case '1day':
            $dt->modify('+1 day');
            break;
        case '7d':
        case '1w':
            $dt->modify('+7 days');
            break;
        case '30d':
        case '1m':
            $dt->modify('+30 days');
            break;
        default:
            $dt->modify('+30 days');
            break;
    }
    return $dt->format('Y-m-d H:i:s');
}

function getDurationLabel($duration) {
    switch (strtolower(trim((string)$duration))) {
        case '1h': return '1 Giờ';
        case '1d': return '1 Ngày';
        case '7d': return '7 Ngày';
        case '30d': return '30 Ngày';
        case 'permanent': return 'Vĩnh Viễn';
        default: return (string)$duration;
    }
}

function formatDurationLabel($duration) {
    return getDurationLabel($duration);
}

function getRemainingTimeText($expiryDate) {
    if (empty($expiryDate) || $expiryDate === 'permanent') {
        return 'Vĩnh viễn';
    }
    try {
        $now = new DateTime();
        $exp = new DateTime($expiryDate);
        if ($now > $exp) {
            return 'Đã hết hạn';
        }
        $diff = $now->diff($exp);
        if ($diff->days > 0) return "Còn {$diff->days} ngày {$diff->h}h";
        if ($diff->h > 0) return "Còn {$diff->h} giờ {$diff->i}p";
        return "Còn {$diff->i} phút";
    } catch (Exception $e) {
        return 'Không xác định';
    }
}

function formatRemainingTime($expiryDate) {
    return getRemainingTimeText($expiryDate);
}

function getUsers() {
    return readJsonFile(USERS_FILE, []);
}

function saveUsers($users) {
    return writeJsonFile(USERS_FILE, $users);
}

function findUserByUsername($username) {
    $users = getUsers();
    $target = strtolower(trim((string)$username));
    foreach ($users as $u) {
        if (strtolower(trim((string)($u['username'] ?? ''))) === $target) {
            return $u;
        }
    }
    return null;
}

function upsertUser($userData) {
    return withLockedJson(USERS_FILE, [], function (&$users, &$dirty) use ($userData) {
        $target = strtolower(trim((string)$userData['username']));
        $found = false;
        foreach ($users as $i => $u) {
            if (strtolower(trim((string)($u['username'] ?? ''))) === $target) {
                $users[$i] = array_merge($u, $userData);
                $found = true;
                break;
            }
        }
        if (!$found) {
            if (empty($userData['id'])) {
                $userData['id'] = time() . random_int(100, 999);
            }
            $users[] = $userData;
        }
        $dirty = true;
        return true;
    });
}

/**
 * Verifies password strictly via salted hash (plaintext password comparisons forbidden).
 */
function verifyUserPassword($inputPassword, $storedHash): bool {
    $hash = (string)$storedHash;
    if ($hash === '' || !str_starts_with($hash, '$')) {
        return false;
    }
    return password_verify((string)$inputPassword, $hash);
}

function hashUserPassword($password): string {
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    return password_hash((string)$password, $algo);
}

function verifyAdminCredentials(string $username, string $password, array $settings): array {
    $envUser = envValue('ADMIN_USERNAME', '');
    $envHash = envValue('ADMIN_PASS_HASH', '');
    $targetUser = $envUser !== '' ? $envUser : (string)($settings['admin_user'] ?? '');
    $targetHash = (string)($settings['admin_pass_hash'] ?? '');
    if ($targetHash === '') {
        $targetHash = $envHash;
    }

    if ($targetUser !== '' && hash_equals($targetUser, $username) && verifyUserPassword($password, $targetHash)) {
        return ['ok' => true, 'username' => $targetUser, 'error' => ''];
    }

    $foundUser = findUserByUsername($username);
    if ($foundUser) {
        if (empty($foundUser['is_active'])) {
            return ['ok' => false, 'username' => '', 'error' => 'Tài khoản này đã bị khóa!'];
        }
        if (verifyUserPassword($password, (string)($foundUser['password'] ?? ''))) {
            if (strtolower((string)($foundUser['role'] ?? '')) !== 'admin') {
                return ['ok' => false, 'username' => '', 'error' => 'Tài khoản không có quyền Quản trị Admin!'];
            }
            if (!empty($foundUser['expiry_date']) && $foundUser['expiry_date'] !== 'permanent') {
                if (new DateTime() > new DateTime($foundUser['expiry_date'])) {
                    return ['ok' => false, 'username' => '', 'error' => 'Tài khoản Quản trị này đã hết hạn!'];
                }
            }
            return ['ok' => true, 'username' => (string)$foundUser['username'], 'error' => ''];
        }
    }
    return ['ok' => false, 'username' => '', 'error' => 'Sai tài khoản hoặc mật khẩu quản trị!'];
}

function normalizeKey(&$k) {
    if (!isset($k['max_devices'])) {
        $k['max_devices'] = 1;
    } else {
        $k['max_devices'] = intval($k['max_devices']);
    }
    if (!isset($k['status']) || $k['status'] === '') {
        $k['status'] = 'active';
    }
    if (!isset($k['devices']) || !is_array($k['devices'])) {
        $k['devices'] = [];
        if (!empty($k['used_by']) && is_string($k['used_by'])) {
            foreach (array_map('trim', explode(',', $k['used_by'])) as $h) {
                if ($h !== '') {
                    $k['devices'][] = [
                        'hwid' => $h,
                        'activated_at' => $k['used_at'] ?? ($k['created_at'] ?? date('Y-m-d H:i:s')),
                        'last_seen' => $k['used_at'] ?? date('Y-m-d H:i:s'),
                        'ip' => 'Unknown',
                    ];
                }
            }
        }
    }
    return $k;
}

function formatKeyDevicesLabel($k) {
    $devCount = isset($k['devices']) && is_array($k['devices']) ? count($k['devices']) : 0;
    $max = isset($k['max_devices']) ? intval($k['max_devices']) : 1;
    if ($max === 0) {
        return "{$devCount} / Vô hạn";
    }
    return "{$devCount} / {$max} máy";
}

function getKeys() {
    $keys = readJsonFile(KEYS_FILE, []);
    foreach ($keys as &$k) {
        normalizeKey($k);
    }
    unset($k);
    return $keys;
}

function saveKeys($keys) {
    return writeJsonFile(KEYS_FILE, $keys);
}

function getBuildManifests(): array {
    return readJsonFile(MANIFESTS_FILE, []);
}

function saveBuildManifests(array $manifests): bool {
    return writeJsonFile(MANIFESTS_FILE, array_values($manifests));
}

function getBannedDevices(): array {
    return readJsonFile(BANNED_DEVICES_FILE, []);
}

function findActiveBannedDevice(string $hwid): ?array {
    $needle = trim($hwid);
    if ($needle === '') {
        return null;
    }
    foreach (getBannedDevices() as $b) {
        if (!empty($b['active']) && strcasecmp(trim((string)($b['hwid'] ?? '')), $needle) === 0) {
            return $b;
        }
    }
    return null;
}

function banDeviceHwid(string $hwid, string $reason = '', string $bannedBy = 'admin', string $sourceKey = ''): bool {
    $clean = trim($hwid);
    if ($clean === '') {
        return false;
    }
    return withLockedJson(BANNED_DEVICES_FILE, [], function (&$list, &$dirty) use ($clean, $reason, $bannedBy, $sourceKey) {
        $nowStr = date('Y-m-d H:i:s');
        $updated = false;
        foreach ($list as &$item) {
            if (strcasecmp(trim((string)($item['hwid'] ?? '')), $clean) === 0) {
                $item['active'] = true;
                $item['reason'] = trim($reason);
                $item['banned_by'] = $bannedBy;
                $item['banned_at'] = $nowStr;
                if ($sourceKey !== '') {
                    $item['source_key'] = $sourceKey;
                }
                $updated = true;
                break;
            }
        }
        unset($item);
        if (!$updated) {
            $list[] = [
                'hwid' => $clean,
                'reason' => trim($reason),
                'banned_by' => $bannedBy,
                'banned_at' => $nowStr,
                'active' => true,
                'source_key' => $sourceKey,
            ];
        }
        $dirty = true;
        return true;
    });
}

function unbanDeviceHwid(string $hwid): bool {
    $clean = trim($hwid);
    if ($clean === '') {
        return false;
    }
    return withLockedJson(BANNED_DEVICES_FILE, [], function (&$list, &$dirty) use ($clean) {
        $next = [];
        $removed = false;
        foreach ($list as $item) {
            if (strcasecmp(trim((string)($item['hwid'] ?? '')), $clean) === 0) {
                $removed = true;
                continue;
            }
            $next[] = $item;
        }
        if ($removed) {
            $list = $next;
            $dirty = true;
        }
        return $removed;
    });
}

function addLog($type, $username, $message, $ip = null, $hwid = null) {
    $ip = $ip ?: ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
    $entry = [
        'id' => bin2hex(random_bytes(6)),
        'time' => date('Y-m-d H:i:s'),
        'ts' => time(),
        'type' => (string)$type,
        'action' => (string)$type,
        'username' => (string)$username,
        'message' => (string)$message,
        'details' => (string)$message,
        'ip' => (string)$ip,
        'hwid' => $hwid,
    ];
    withLockedJson(LOGS_FILE, [], function (&$logs, &$dirty) use ($entry) {
        array_unshift($logs, $entry);
        if (count($logs) > 2000) {
            $logs = array_slice($logs, 0, 2000);
        }
        $dirty = true;
        return true;
    });
}

function getCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(?string $token): bool {
    $expected = $_SESSION['csrf_token'] ?? '';
    return $expected !== '' && is_string($token) && hash_equals($expected, $token);
}

/**
 * Optional PDO connection when DB_DSN is configured in .env.
 */
function getOptionalPdo(): ?PDO {
    static $pdo = null;
    static $attempted = false;
    if ($attempted) {
        return $pdo;
    }
    $attempted = true;
    $dsn = envValue('DB_DSN', '');
    if ($dsn === '' || !class_exists('PDO')) {
        return null;
    }
    try {
        $pdo = new PDO($dsn, envValue('DB_USER', ''), envValue('DB_PASS', ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } catch (Throwable $e) {
        error_log('Optional PDO init failed: ' . $e->getMessage());
        $pdo = null;
    }
    return $pdo;
}

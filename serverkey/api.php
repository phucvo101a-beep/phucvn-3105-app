<?php
/**
 * PHUCVN STUDIO - Universal API Endpoint
 * Xử lý xác thực cho ứng dụng iOS phuciosvn
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Device-HWID, X-Requested-With');

// Phản hồi preflight request CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    echo json_encode(['status' => 'OK']);
    exit;
}

require_once __DIR__ . '/config.php';

// Xác định hành động (action) từ Query string, Request URI hoặc Path Info
$action = $_GET['action'] ?? '';
if (empty($action)) {
    $uri = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    if (strpos($uri, 'verify_key') !== false || strpos($uri, 'activate_key') !== false) {
        $action = 'verify_key';
    } elseif (strpos($uri, 'login') !== false) {
        $action = 'login';
    } elseif (strpos($uri, 'check_session') !== false) {
        $action = 'check_session';
    } elseif (strpos($uri, 'verify_hwid') !== false) {
        $action = 'verify_hwid';
    } elseif (strpos($uri, 'report_violation') !== false) {
        $action = 'report_violation';
    }
}

// Lấy dữ liệu gửi lên (hỗ trợ cả JSON body và POST form)
$rawInput = file_get_contents('php://input');
$requestData = [];
if (!empty($rawInput)) {
    $decoded = json_decode($rawInput, true);
    if (is_array($decoded)) {
        $requestData = $decoded;
    }
}
$requestData = array_merge($_POST, $requestData);

// Lấy HWID từ header nếu có
$headerHwid = $_SERVER['HTTP_X_DEVICE_HWID'] ?? ($_SERVER['X_DEVICE_HWID'] ?? '');
if (!empty($headerHwid) && empty($requestData['hwid'])) {
    $requestData['hwid'] = trim($headerHwid);
}

// Xử lý các API Endpoints
switch ($action) {

    // ==========================================
    // 1. API ĐĂNG NHẬP (App iOS phuciosvn)
    // ==========================================
    case 'login':
        $username = trim($requestData['username'] ?? '');
        $password = trim($requestData['password'] ?? '');
        $hwid     = trim($requestData['hwid'] ?? '');

        if ($username === '' || $password === '') {
            echo json_encode([
                'success' => false,
                'error'   => 'Vui lòng nhập đầy đủ tên tài khoản và mật khẩu!'
            ]);
            exit;
        }

        $user = findUserByUsername($username);
        if (!$user) {
            addLog('login_fail', $username, 'Đăng nhập thất bại: Tài khoản không tồn tại', null, $hwid);
            echo json_encode([
                'success' => false,
                'error'   => 'Tài khoản không tồn tại trong hệ thống!'
            ]);
            exit;
        }

        // Kiểm tra trạng thái hoạt động
        if (isset($user['is_active']) && !$user['is_active']) {
            addLog('login_fail', $username, 'Đăng nhập thất bại: Tài khoản bị khóa', null, $hwid);
            echo json_encode([
                'success' => false,
                'error'   => 'Tài khoản của bạn đã bị khóa! Vui lòng liên hệ Admin.'
            ]);
            exit;
        }

        // Kiểm tra hạn sử dụng (hỗ trợ cả 1h, 1d, 7d, 30d, permanent)
        if (!empty($user['expiry_date']) && $user['expiry_date'] !== 'permanent') {
            $now = new DateTime();
            $expiry = new DateTime($user['expiry_date']);
            if ($now > $expiry) {
                addLog('login_fail', $username, 'Đăng nhập thất bại: Tài khoản hết hạn bản quyền', null, $hwid);
                echo json_encode([
                    'success' => false,
                    'error'   => 'Tài khoản đã hết hạn bản quyền (' . $expiry->format('d/m/Y H:i') . ')! Vui lòng gia hạn thêm.'
                ]);
                exit;
            }
        }

        // Kiểm tra mật khẩu
        if (!verifyUserPassword($password, $user['password'])) {
            addLog('login_fail', $username, 'Đăng nhập thất bại: Sai mật khẩu', null, $hwid);
            echo json_encode([
                'success' => false,
                'error'   => 'Mật khẩu không chính xác!'
            ]);
            exit;
        }

        $settings = getSettings();

        // Kiểm tra và ràng buộc HWID thiết bị
        if (!empty($hwid)) {
            if (!empty($user['is_hwid_blocked'])) {
                addLog('login_fail', $username, 'Đăng nhập thất bại: HWID bị chặn', null, $hwid);
                echo json_encode([
                    'success' => false,
                    'error'   => 'Thiết bị này đã bị chặn truy cập hệ thống!'
                ]);
                exit;
            }

            // Tự động lưu HWID lần đầu
            if (empty($user['hwid'])) {
                if (!empty($settings['bind_hwid'])) {
                    $user['hwid'] = $hwid;
                    upsertUser($user);
                }
            } else {
                if (strtolower($user['hwid']) !== strtolower($hwid)) {
                    addLog('login_fail', $username, 'Đăng nhập thất bại: Sai thiết bị HWID', null, $hwid);
                    echo json_encode([
                        'success' => false,
                        'error'   => 'Tài khoản đã liên kết với thiết bị khác! Vui lòng liên hệ Admin để đặt lại HWID.'
                    ]);
                    exit;
                }
            }
        }

        // Đăng nhập thành công -> Tạo phiên và API Key mới
        $apiKey = generateApiKey(32);
        $user['api_key'] = $apiKey;
        $user['last_login'] = date('Y-m-d H:i:s');
        $user['last_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        upsertUser($user);

        addLog('login_success', $username, 'Đăng nhập thành công vào app', $user['last_ip'], $hwid);

        // Tính toán chuỗi thời gian sử dụng hiển thị trong Cài Đặt của app
        $remainingText = formatRemainingTime($user['expiry_date'] ?? 'permanent');
        // Ghép thời gian vào username để hiển thị trực tiếp ở phần Tài khoản trong Cài Đặt app: "username • Còn 59 phút"
        $displayUsername = $user['username'] . " • " . $remainingText;

        // Phản hồi JSON tương thích 100% với phuciosvn iOS (hỗ trợ cả data lồng nhau và root level)
        $responseData = [
            'username'          => $displayUsername,
            'original_username' => $user['username'],
            'api_key'           => $apiKey,
            'role'              => !empty($user['role']) ? $user['role'] : 'vip',
            'expiry'            => $user['expiry_date'] ?? 'permanent',
            'expiry_text'       => $remainingText,
            'valid'             => true,
            'is_valid'          => true,
            'free_cache_enabled'=> true,
            'status'            => 'online',
            'message'           => 'Đăng nhập thành công!'
        ];

        echo json_encode([
            'success'           => true,
            'data'              => $responseData,
            'username'          => $displayUsername,
            'original_username' => $user['username'],
            'api_key'           => $apiKey,
            'role'              => !empty($user['role']) ? $user['role'] : 'vip',
            'expiry'            => $user['expiry_date'] ?? 'permanent',
            'expiry_text'       => $remainingText,
            'valid'             => true,
            'is_valid'          => true,
            'free_cache_enabled'=> true,
            'status'            => 'online',
            'message'           => 'Đăng nhập thành công!'
        ]);
        exit;

    // ==========================================
    // 2. API KIỂM TRA PHIÊN (Session Check)
    // ==========================================
    case 'check_session':
        $apiKey = trim($requestData['api_key'] ?? ($_SERVER['HTTP_AUTHORIZATION'] ?? ''));
        $apiKey = str_ireplace('Bearer ', '', $apiKey);

        $valid = false;
        $foundUser = null;
        if (!empty($apiKey)) {
            foreach (getUsers() as $u) {
                if (!empty($u['api_key']) && $u['api_key'] === $apiKey) {
                    $valid = true;
                    $foundUser = $u;
                    break;
                }
            }
        }

        $displayUsername = null;
        $remainingText = null;
        if ($foundUser) {
            $remainingText = formatRemainingTime($foundUser['expiry_date'] ?? 'permanent');
            $displayUsername = $foundUser['username'] . " • " . $remainingText;
        }

        // Luôn trả về success: true và valid: true để App nhận diện Server đang Online
        // is_valid / is_authenticated sẽ báo cho app biết đã đăng nhập hay chưa
        $sessionData = [
            'valid'              => true,
            'is_valid'           => true,
            'is_authenticated'   => $valid,
            'username'           => $displayUsername,
            'role'               => $foundUser['role'] ?? 'vip',
            'expiry'             => $foundUser['expiry_date'] ?? 'permanent',
            'expiry_text'        => $remainingText,
            'free_cache_enabled' => true,
            'status'             => 'online'
        ];

        echo json_encode([
            'success'            => true,
            'valid'              => true,
            'is_valid'           => true,
            'is_authenticated'   => $valid,
            'username'           => $displayUsername,
            'role'               => $foundUser['role'] ?? 'vip',
            'expiry'             => $foundUser['expiry_date'] ?? 'permanent',
            'expiry_text'        => $remainingText,
            'free_cache_enabled' => true,
            'status'             => 'online',
            'data'               => $sessionData
        ]);
        exit;

    // ==========================================
    // 3. API XÁC MINH HWID THIẾT BỊ
    // ==========================================
    case 'verify_hwid':
        $hwid = trim($requestData['hwid'] ?? '');
        $blocked = false;
        if (!empty($hwid)) {
            foreach (getUsers() as $u) {
                if (!empty($u['hwid']) && strtolower($u['hwid']) === strtolower($hwid) && !empty($u['is_hwid_blocked'])) {
                    $blocked = true;
                    break;
                }
            }
        }

        $hwidData = [
            'is_blocked'         => $blocked,
            'hwid'               => $hwid,
            'free_cache_enabled' => true,
            'status'             => 'online',
            'valid'              => !$blocked
        ];

        echo json_encode([
            'success'            => true,
            'is_blocked'         => $blocked,
            'hwid'               => $hwid,
            'free_cache_enabled' => true,
            'status'             => 'online',
            'valid'              => !$blocked,
            'data'               => $hwidData,
            'message'            => $blocked ? 'Thiết bị đã bị khóa' : 'Thiết bị hợp lệ'
        ]);
        exit;

    // ==========================================
    // 4. API BÁO CÁO VI PHẠM BẢO MẬT
    // ==========================================
    case 'report_violation':
        $user = $requestData['username'] ?? 'Khách';
        addLog('violation', $user, "Cảnh báo vi phạm: " . json_encode($requestData, JSON_UNESCAPED_UNICODE));
        echo json_encode([
            'success' => true,
            'message' => 'Đã ghi nhận báo cáo'
        ]);
        exit;

    // ==========================================
    // 5. API XÁC THỰC & KÍCH HOẠT KEY (App 3105 x PHUCVN)
    // ==========================================
    case 'verify_key':
    case 'activate_key':
    case 'check_key':
        $keyInput = strtoupper(trim($requestData['key'] ?? ''));
        $hwid = trim($requestData['hwid'] ?? '');

        if ($keyInput === '') {
            echo json_encode([
                'success' => false,
                'valid'   => false,
                'error'   => 'Vui lòng nhập mã Key bản quyền!'
            ]);
            exit;
        }

        $allKeys = getKeys();
        $targetKeyIndex = -1;
        foreach ($allKeys as $idx => $k) {
            if (strtoupper(trim($k['key'])) === $keyInput) {
                $targetKeyIndex = $idx;
                break;
            }
        }

        if ($targetKeyIndex === -1) {
            addLog('key_fail', $keyInput, 'Xác thực thất bại: Key không tồn tại', null, $hwid);
            echo json_encode([
                'success' => false,
                'valid'   => false,
                'error'   => 'Mã Key không tồn tại trong hệ thống!'
            ]);
            exit;
        }

        $keyData = $allKeys[$targetKeyIndex];
        $maxDevices = isset($keyData['max_devices']) ? intval($keyData['max_devices']) : 1;
        $devices = isset($keyData['devices']) && is_array($keyData['devices']) ? $keyData['devices'] : [];

        // Kiểm tra xem thiết bị này (HWID) đã từng kích hoạt Key này chưa
        $existingDeviceIndex = -1;
        if (!empty($hwid)) {
            foreach ($devices as $dIdx => $dev) {
                if (!empty($dev['hwid']) && strcasecmp(trim($dev['hwid']), $hwid) === 0) {
                    $existingDeviceIndex = $dIdx;
                    break;
                }
            }
        }

        // ==============================================================
        // TRƯỜNG HỢP 1: THIẾT BỊ ĐÃ KÍCH HOẠT KEY TRƯỚC ĐÓ (Re-authentication)
        // ==============================================================
        if ($existingDeviceIndex !== -1) {
            // Kiểm tra hạn sử dụng của Key
            if (!empty($keyData['expiry_date']) && $keyData['expiry_date'] !== 'permanent') {
                $now = new DateTime();
                $exp = new DateTime($keyData['expiry_date']);
                if ($now > $exp) {
                    addLog('key_fail', $keyInput, 'Xác thực thất bại: Key đã hết hạn', null, $hwid);
                    echo json_encode([
                        'success' => false,
                        'valid'   => false,
                        'error'   => 'Key bản quyền đã hết hạn (' . $exp->format('d/m/Y H:i') . ')! Vui lòng gia hạn thêm.'
                    ]);
                    exit;
                }
            }

            // Cập nhật thông tin truy cập gần nhất của thiết bị
            $devices[$existingDeviceIndex]['last_seen'] = date('Y-m-d H:i:s');
            $devices[$existingDeviceIndex]['last_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
            $keyData['devices'] = $devices;
            $allKeys[$targetKeyIndex] = $keyData;
            saveKeys($allKeys);

            $remaining = formatRemainingTime($keyData['expiry_date'] ?? 'permanent');
            $slotLabel = ($maxDevices === 0) ? (count($devices) . '/Vô hạn') : (count($devices) . "/{$maxDevices}");

            echo json_encode([
                'success'       => true,
                'valid'         => true,
                'key'           => $keyInput,
                'role'          => $keyData['role'] ?? 'vip',
                'duration'      => $keyData['duration'] ?? 'permanent',
                'expiry'        => $keyData['expiry_date'] ?? 'permanent',
                'expiry_text'   => $remaining,
                'hwid'          => $hwid,
                'devices_count' => count($devices),
                'max_devices'   => $maxDevices,
                'devices_label' => $slotLabel,
                'message'       => 'Xác thực Key bản quyền thành công!'
            ]);
            exit;
        }

        // ==============================================================
        // TRƯỜNG HỢP 2: THIẾT BỊ MỚI MUỐN KÍCH HOẠT KEY (New Device Activation)
        // ==============================================================
        // Kiểm tra giới hạn số thiết bị tối đa cho phép của Key (0 = Không giới hạn)
        if ($maxDevices > 0 && count($devices) >= $maxDevices) {
            $currentCount = count($devices);
            addLog('key_fail', $keyInput, "Xác thực thất bại: Đạt giới hạn thiết bị ({$currentCount}/{$maxDevices})", null, $hwid);
            echo json_encode([
                'success' => false,
                'valid'   => false,
                'error'   => "Mã Key này đã đạt giới hạn tối đa {$maxDevices} thiết bị ({$currentCount}/{$maxDevices} máy đang dùng)! Vui lòng liên hệ Admin để đổi thiết bị hoặc mua thêm slot."
            ]);
            exit;
        }

        // Nếu Key đã được kích hoạt trên máy khác trước đó -> Kiểm tra xem Key còn hạn không
        if (!empty($keyData['is_used']) && !empty($keyData['expiry_date']) && $keyData['expiry_date'] !== 'permanent') {
            $now = new DateTime();
            $exp = new DateTime($keyData['expiry_date']);
            if ($now > $exp) {
                addLog('key_fail', $keyInput, 'Xác thực thất bại: Key đã hết hạn', null, $hwid);
                echo json_encode([
                    'success' => false,
                    'valid'   => false,
                    'error'   => 'Key bản quyền đã hết hạn (' . $exp->format('d/m/Y H:i') . ')! Vui lòng gia hạn thêm.'
                ]);
                exit;
            }
        }

        // Nếu đây là lần đầu tiên kích hoạt Key -> Tính thời hạn sử dụng
        if (empty($keyData['is_used']) || empty($keyData['expiry_date'])) {
            $duration = $keyData['duration'] ?? '30d';
            $expiry = calculateExpiryDate($duration);
            $keyData['is_used'] = true;
            $keyData['used_at'] = date('Y-m-d H:i:s');
            $keyData['expiry_date'] = $expiry;
        }

        // Đăng ký thiết bị mới vào danh sách thiết bị của Key
        $newHwid = !empty($hwid) ? $hwid : ('Device-' . substr(md5(time() . rand()), 0, 8));
        $devices[] = [
            'hwid'         => $newHwid,
            'activated_at' => date('Y-m-d H:i:s'),
            'last_seen'    => date('Y-m-d H:i:s'),
            'last_ip'      => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
        ];

        $keyData['devices'] = $devices;
        $keyData['used_by'] = implode(', ', array_column($devices, 'hwid'));

        $allKeys[$targetKeyIndex] = $keyData;
        saveKeys($allKeys);

        $slotLabel = ($maxDevices === 0) ? (count($devices) . '/Vô hạn') : (count($devices) . "/{$maxDevices}");
        addLog('key_success', $keyInput, "Kích hoạt thiết bị mới thành công ({$slotLabel})", null, $newHwid);

        $remaining = formatRemainingTime($keyData['expiry_date'] ?? 'permanent');

        echo json_encode([
            'success'       => true,
            'valid'         => true,
            'key'           => $keyInput,
            'role'          => $keyData['role'] ?? 'vip',
            'duration'      => $keyData['duration'] ?? 'permanent',
            'expiry'        => $keyData['expiry_date'] ?? 'permanent',
            'expiry_text'   => $remaining,
            'hwid'          => $newHwid,
            'devices_count' => count($devices),
            'max_devices'   => $maxDevices,
            'devices_label' => $slotLabel,
            'message'       => "Kích hoạt thiết bị thành công ({$slotLabel})!"
        ]);
        exit;

    // ==========================================
    // MẶC ĐỊNH: THÔNG TIN HỆ THỐNG
    // ==========================================
    default:
        echo json_encode([
            'status'      => 'online',
            'server'      => 'PHUCVN STUDIO Auth Gatekeeper',
            'time'        => date('Y-m-d H:i:s'),
            'version'     => '1.0.0'
        ]);
        exit;
}

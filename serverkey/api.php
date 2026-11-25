<?php
/**
 * Legacy plaintext API endpoints permanently disabled to prevent auth/response spoofing & key enumeration.
 */
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
http_response_code(410);
echo json_encode([
    'success' => false,
    'valid' => false,
    'code' => 'LEGACY_API_RETIRED',
    'message' => 'Plaintext API v1 is permanently disabled. Please update the application to V3.',
]);

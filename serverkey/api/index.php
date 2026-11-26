<?php
header('Content-Type: application/json; charset=utf-8');
http_response_code(410);
echo json_encode(['error' => 'LEGACY_API_RETIRED', 'message' => 'Use /api/v3 encrypted endpoint only.']);

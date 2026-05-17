<?php

function logActivity($pdo, $userId, $activityType, $description) {
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

    $stmt = $pdo->prepare("
        INSERT INTO activity_logs (user_id, activity_type, description, ip_address)
        VALUES (?, ?, ?, ?)
    ");

    $stmt->execute([$userId, $activityType, $description, $ipAddress]);
}

function generateAccountNumber($pdo) {
    do {
        $accountNumber = (string) random_int(10000000, 99999999);

        $stmt = $pdo->prepare("SELECT id FROM users WHERE account_number = ?");
        $stmt->execute([$accountNumber]);

        $exists = $stmt->fetch();

    } while ($exists);

    return $accountNumber;
}

function generateSortCode() {
    return "20-26-01";
}

?>
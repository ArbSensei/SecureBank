<?php
session_start();

require_once "../config/db.php";

$message = "";
$messageType = "";

// If no MFA process is active, send user back to login
if (!isset($_SESSION["pending_mfa_user_id"])) {
    header("Location: login.php");
    exit;
}

$pendingUserId = $_SESSION["pending_mfa_user_id"];

// Create CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Save activity logs
function logActivity($pdo, $userId, $activityType, $description) {
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

    $stmt = $pdo->prepare("
        INSERT INTO activity_logs (user_id, activity_type, description, ip_address)
        VALUES (?, ?, ?, ?)
    ");

    $stmt->execute([$userId, $activityType, $description, $ipAddress]);
}

// Get user details
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? LIMIT 1");
$stmt->execute([$pendingUserId]);
$user = $stmt->fetch();

if (!$user) {
    session_unset();
    session_destroy();
    header("Location: login.php");
    exit;
}

// Check if MFA code expired
if (isset($_SESSION["mfa_code_expires"]) && time() > $_SESSION["mfa_code_expires"]) {
    logActivity($pdo, $pendingUserId, "MFA Expired", "Two-step verification code expired.");

    unset($_SESSION["pending_mfa_user_id"]);
    unset($_SESSION["mfa_code_hash"]);
    unset($_SESSION["mfa_demo_code"]);
    unset($_SESSION["mfa_code_expires"]);
    unset($_SESSION["mfa_attempts"]);

    $message = "Your verification code has expired. Please log in again.";
    $messageType = "error";
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_SESSION["pending_mfa_user_id"])) {
    $enteredCode = trim($_POST["mfa_code"] ?? "");
    $csrfToken = $_POST["csrf_token"] ?? "";

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $message = "Invalid form request. Please try again.";
        $messageType = "error";
    }
    elseif (!preg_match("/^[0-9]{6}$/", $enteredCode)) {
        $message = "Please enter a valid 6-digit verification code.";
        $messageType = "error";
    }
    elseif (!password_verify($enteredCode, $_SESSION["mfa_code_hash"])) {
        $_SESSION["mfa_attempts"] = ($_SESSION["mfa_attempts"] ?? 0) + 1;

        if ($_SESSION["mfa_attempts"] >= 3) {
            $lockStmt = $pdo->prepare("
                UPDATE users
                SET is_locked = 1, failed_attempts = 3
                WHERE id = ?
            ");
            $lockStmt->execute([$pendingUserId]);

            logActivity($pdo, $pendingUserId, "MFA Failed - Account Locked", "Account locked after three incorrect MFA code attempts.");

            unset($_SESSION["pending_mfa_user_id"]);
            unset($_SESSION["mfa_code_hash"]);
            unset($_SESSION["mfa_demo_code"]);
            unset($_SESSION["mfa_code_expires"]);
            unset($_SESSION["mfa_attempts"]);

            $message = "Too many incorrect verification attempts. Your account has been locked.";
            $messageType = "error";
        } else {
            $remaining = 3 - $_SESSION["mfa_attempts"];

            logActivity($pdo, $pendingUserId, "MFA Failed", "Incorrect two-step verification code was entered.");

            $message = "Incorrect verification code. Attempts remaining: " . $remaining;
            $messageType = "error";
        }
    }
    else {
        // MFA successful
        session_regenerate_id(true);

        $_SESSION["user_id"] = $user["id"];
        $_SESSION["full_name"] = $user["full_name"];
        $_SESSION["username"] = $user["username"];
        $_SESSION["account_number"] = $user["account_number"];

        logActivity($pdo, $user["id"], "MFA Successful", "User completed two-step verification successfully.");
        logActivity($pdo, $user["id"], "Login Successful", "User logged in successfully after MFA.");

        unset($_SESSION["pending_mfa_user_id"]);
        unset($_SESSION["mfa_code_hash"]);
        unset($_SESSION["mfa_demo_code"]);
        unset($_SESSION["mfa_code_expires"]);
        unset($_SESSION["mfa_attempts"]);

        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));

        header("Location: dashboard.php");
        exit;
    }
}

$demoCode = $_SESSION["mfa_demo_code"] ?? "";
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Two-Step Verification - Cardiff Met Technology Bank</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>

<div class="container">
    <div class="card">
        <img src="../assets/cardiff-met-logo.png" class="brand-logo" alt="Cardiff Met Logo" onerror="this.style.display='none'">

        <h1>Two-Step Verification</h1>

        <p>
            For extra security, enter the 6-digit verification code before accessing your account.
        </p>

        <?php if (!empty($demoCode) && empty($message)): ?>
            <div class="message warning">
                <strong>Prototype MFA code:</strong> <?php echo htmlspecialchars($demoCode); ?><br>
                In a real banking system, this code would be sent by SMS, email, or an authenticator app.
            </div>
        <?php endif; ?>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo htmlspecialchars($messageType); ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <?php if (isset($_SESSION["pending_mfa_user_id"])): ?>
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                <div class="form-group">
                    <label>6-digit verification code</label>
                    <input type="text" name="mfa_code" maxlength="6" pattern="[0-9]{6}" required>
                </div>

                <button type="submit" class="btn">Verify</button>
                <a href="login.php" class="btn secondary">Cancel</a>
            </form>
        <?php else: ?>
            <a href="login.php" class="btn">Back To Login</a>
        <?php endif; ?>
    </div>
</div>

</body>
</html>
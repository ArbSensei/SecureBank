<?php
session_start();

require_once "../config/db.php";

$message = "";
$messageType = "";

// If already logged in, go to dashboard
if (isset($_SESSION["user_id"])) {
    header("Location: dashboard.php");
    exit;
}

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

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $loginInput = trim($_POST["login"] ?? "");
    $passwordInput = $_POST["password"] ?? "";
    $csrfToken = $_POST["csrf_token"] ?? "";

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $message = "Invalid form request. Please try again.";
        $messageType = "error";
    }
    elseif (empty($loginInput) || empty($passwordInput)) {
        $message = "Please enter your username/email and password.";
        $messageType = "error";
    }
    else {
        try {
            $stmt = $pdo->prepare("
                SELECT * FROM users
                WHERE username = ? OR email = ?
                LIMIT 1
            ");
            $stmt->execute([$loginInput, $loginInput]);
            $user = $stmt->fetch();

            if ($user) {
                if ($user["is_locked"] == 1) {
                    $message = "This account is locked because of too many failed login attempts.";
                    $messageType = "error";

                    logActivity($pdo, $user["id"], "Locked Login Attempt", "A locked account was used for login.");
                }
                elseif (password_verify($passwordInput, $user["password_hash"])) {
                    // Reset failed attempts after password is correct
                    $resetStmt = $pdo->prepare("
                        UPDATE users
                        SET failed_attempts = 0
                        WHERE id = ?
                    ");
                    $resetStmt->execute([$user["id"]]);

                    // Create 6-digit MFA code
                    $mfaCode = (string) random_int(100000, 999999);

                    // Store MFA details in session
                    $_SESSION["pending_mfa_user_id"] = $user["id"];
                    $_SESSION["mfa_code_hash"] = password_hash($mfaCode, PASSWORD_DEFAULT);
                    $_SESSION["mfa_demo_code"] = $mfaCode;
                    $_SESSION["mfa_code_expires"] = time() + 300; // 5 minutes
                    $_SESSION["mfa_attempts"] = 0;

                    logActivity($pdo, $user["id"], "MFA Code Generated", "A two-step verification code was generated after correct password login.");

                    header("Location: verify_mfa.php");
                    exit;
                }
                else {
                    $newFailedAttempts = $user["failed_attempts"] + 1;

                    if ($newFailedAttempts >= 3) {
                        $updateStmt = $pdo->prepare("
                            UPDATE users
                            SET failed_attempts = ?, is_locked = 1
                            WHERE id = ?
                        ");
                        $updateStmt->execute([$newFailedAttempts, $user["id"]]);

                        $message = "Too many failed login attempts. Your account has been locked.";
                        $messageType = "error";

                        logActivity($pdo, $user["id"], "Account Locked", "Account locked after three failed login attempts.");
                    } else {
                        $updateStmt = $pdo->prepare("
                            UPDATE users
                            SET failed_attempts = ?
                            WHERE id = ?
                        ");
                        $updateStmt->execute([$newFailedAttempts, $user["id"]]);

                        $message = "Incorrect password. Failed attempts: " . $newFailedAttempts . "/3";
                        $messageType = "error";

                        logActivity($pdo, $user["id"], "Login Failed", "Incorrect password was entered.");
                    }
                }
            } else {
                $message = "No account found with those details.";
                $messageType = "error";

                logActivity($pdo, null, "Login Failed", "Login attempt with unknown username or email.");
            }

        } catch (PDOException $e) {
            $message = "Something went wrong. Please try again.";
            $messageType = "error";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Cardiff Met Technology Bank</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>

<div class="container">
    <div class="card">
        <img src="../assets/cardiff-met-logo.png" class="brand-logo" alt="Cardiff Met Logo" onerror="this.style.display='none'">

        <h1>Cardiff Met Technology Bank Login</h1>

        <p>
            Enter your login details. After your password is checked, you will be asked to complete two-step verification.
        </p>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo htmlspecialchars($messageType); ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <div class="form-group">
                <label>Username or Email</label>
                <input type="text" name="login" required>
            </div>

            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>

            <button type="submit" class="btn">Continue</button>
            <a href="../index.php" class="btn secondary">Back Home</a>
        </form>
    </div>
</div>

</body>
</html>
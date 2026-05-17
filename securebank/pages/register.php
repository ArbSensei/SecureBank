<?php
session_start();

require_once "../config/db.php";
require_once "../includes/functions.php";

$message = "";
$messageType = "";

// Backup functions in case functions.php has not been updated yet
if (!function_exists("generateSortCode")) {
    function generateSortCode() {
        return "20-26-01";
    }
}

if (!function_exists("generateAccountNumber")) {
    function generateAccountNumber($pdo) {
        do {
            $accountNumber = (string) random_int(10000000, 99999999);

            $stmt = $pdo->prepare("SELECT id FROM users WHERE account_number = ?");
            $stmt->execute([$accountNumber]);

            $exists = $stmt->fetch();

        } while ($exists);

        return $accountNumber;
    }
}

if (!function_exists("logActivity")) {
    function logActivity($pdo, $userId, $activityType, $description) {
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

        $stmt = $pdo->prepare("
            INSERT INTO activity_logs (user_id, activity_type, description, ip_address)
            VALUES (?, ?, ?, ?)
        ");

        $stmt->execute([$userId, $activityType, $description, $ipAddress]);
    }
}

// Create CSRF token for form protection
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// When the form is submitted
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $fullName = trim($_POST["full_name"] ?? "");
    $usernameInput = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $passwordInput = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";
    $csrfToken = $_POST["csrf_token"] ?? "";

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $message = "Invalid form request. Please try again.";
        $messageType = "error";
    }
    elseif (empty($fullName) || empty($usernameInput) || empty($email) || empty($passwordInput) || empty($confirmPassword)) {
        $message = "Please fill in all fields.";
        $messageType = "error";
    }
    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Please enter a valid email address.";
        $messageType = "error";
    }
    elseif (!preg_match("/^[a-zA-Z0-9_]{3,30}$/", $usernameInput)) {
        $message = "Username must be 3-30 characters and only contain letters, numbers, or underscore.";
        $messageType = "error";
    }
    elseif (strlen($passwordInput) < 8) {
        $message = "Password must be at least 8 characters long.";
        $messageType = "error";
    }
    elseif ($passwordInput !== $confirmPassword) {
        $message = "Passwords do not match.";
        $messageType = "error";
    }
    else {
        try {
            // Securely hash password before saving it
            $passwordHash = password_hash($passwordInput, PASSWORD_DEFAULT);

            // Generate account details
            $accountNumber = generateAccountNumber($pdo);
            $sortCode = generateSortCode();

            // Insert user using prepared statement
            $stmt = $pdo->prepare("
                INSERT INTO users (full_name, username, email, password_hash, account_number, sort_code)
                VALUES (?, ?, ?, ?, ?, ?)
            ");

            $stmt->execute([
                $fullName,
                $usernameInput,
                $email,
                $passwordHash,
                $accountNumber,
                $sortCode
            ]);

            $newUserId = $pdo->lastInsertId();

            logActivity($pdo, $newUserId, "Account Created", "New user account was created.");

            $message = "Account created successfully. Sort code: " . htmlspecialchars($sortCode) . " | Account number: " . htmlspecialchars($accountNumber);
            $messageType = "success";

            // Refresh CSRF token
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        } catch (PDOException $e) {
            if ($e->getCode() == 23000) {
                $message = "Username or email already exists. Please use different details.";
            } else {
                $message = "Something went wrong. Please check that the database has the sort_code column.";
            }

            $messageType = "error";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Create Account - Cardiff Met Technology Bank</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>

<div class="container">
    <div class="card">
        <img src="../assets/cardiff-met-logo.png" class="brand-logo" alt="Cardiff Met Logo" onerror="this.style.display='none'">

        <h1>Create Cardiff Met Technology Bank Account</h1>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo $messageType; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <div class="form-group">
                <label>Full Name</label>
                <input type="text" name="full_name" required>
            </div>

            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>

            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" required>
            </div>

            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>

            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" required>
            </div>

            <button type="submit" class="btn">Create Account</button>
            <a href="../index.php" class="btn secondary">Back Home</a>
        </form>
    </div>
</div>

</body>
</html>
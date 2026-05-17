<?php
session_start();

require_once "../config/db.php";

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$userId = $_SESSION["user_id"];
$message = "";
$messageType = "";
$showCardDetails = false;

// Create CSRF token
if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

function logActivity($pdo, $userId, $activityType, $description) {
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

    $stmt = $pdo->prepare("
        INSERT INTO activity_logs (user_id, activity_type, description, ip_address)
        VALUES (?, ?, ?, ?)
    ");

    $stmt->execute([$userId, $activityType, $description, $ipAddress]);
}

function getUser($pdo, $userId) {
    $stmt = $pdo->prepare("
        SELECT full_name, username, account_number, sort_code, balance, card_status, card_pin_hash
        FROM users
        WHERE id = ?
    ");

    $stmt->execute([$userId]);
    return $stmt->fetch();
}

$user = getUser($pdo, $userId);

if (!$user) {
    session_destroy();
    header("Location: login.php");
    exit;
}

// Fake prototype card details
$lastFour = substr($user["account_number"], -4);
$userIdTwoDigits = substr(str_pad((string)$userId, 2, "0", STR_PAD_LEFT), -2);
$cardNumberRaw = "453250" . $user["account_number"] . $userIdTwoDigits;
$cardNumberFormatted = substr($cardNumberRaw, 0, 4) . " " . substr($cardNumberRaw, 4, 4) . " " . substr($cardNumberRaw, 8, 4) . " " . substr($cardNumberRaw, 12, 4);
$maskedCardNumber = substr($cardNumberFormatted, 0, 7) . "•• •••• " . $lastFour;
$expiryDate = "12/28";
$cvv = substr(str_pad((string)(($userId * 37 + (int)$lastFour) % 1000), 3, "0", STR_PAD_LEFT), -3);
$cardType = "Debit Card";

// Handle dashboard actions
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $csrfToken = $_POST["csrf_token"] ?? "";
    $action = $_POST["action"] ?? "";

    if (!hash_equals($_SESSION["csrf_token"], $csrfToken)) {
        $message = "Invalid request. Please try again.";
        $messageType = "error";
    } else {
        // Create card PIN
        if ($action === "set_pin") {
            $newPin = trim($_POST["new_pin"] ?? "");
            $confirmPin = trim($_POST["confirm_pin"] ?? "");

            if (!preg_match("/^[0-9]{4}$/", $newPin)) {
                $message = "Card PIN must be exactly 4 digits.";
                $messageType = "error";
            } elseif ($newPin !== $confirmPin) {
                $message = "PINs do not match.";
                $messageType = "error";
            } else {
                $pinHash = password_hash($newPin, PASSWORD_DEFAULT);

                $stmt = $pdo->prepare("
                    UPDATE users
                    SET card_pin_hash = ?
                    WHERE id = ?
                ");
                $stmt->execute([$pinHash, $userId]);

                logActivity($pdo, $userId, "Card PIN Created", "A card PIN was created for viewing card details.");

                $message = "Card PIN created successfully.";
                $messageType = "success";
            }
        }

        // View card details behind PIN
        elseif ($action === "view_card") {
            $pin = trim($_POST["card_pin"] ?? "");

            if (empty($user["card_pin_hash"])) {
                $message = "Please create a card PIN before viewing card details.";
                $messageType = "error";
            } elseif (!preg_match("/^[0-9]{4}$/", $pin)) {
                $message = "Please enter a valid 4-digit PIN.";
                $messageType = "error";
            } elseif (!password_verify($pin, $user["card_pin_hash"])) {
                $message = "Incorrect PIN. Card details remain hidden.";
                $messageType = "error";

                logActivity($pdo, $userId, "Card Details Failed", "Incorrect PIN was used when trying to view card details.");
            } else {
                $showCardDetails = true;
                $message = "Card details unlocked. They will be hidden again when the page is refreshed.";
                $messageType = "success";

                logActivity($pdo, $userId, "Card Details Viewed", "User viewed card details after entering the correct PIN.");
            }
        }

        // Freeze card manually
        elseif ($action === "freeze_card") {
            $stmt = $pdo->prepare("
                UPDATE users
                SET card_status = 'Frozen'
                WHERE id = ?
            ");
            $stmt->execute([$userId]);

            logActivity($pdo, $userId, "Card Frozen", "User manually froze their card.");

            $message = "Your card has been frozen.";
            $messageType = "warning";
        }

        // Unfreeze card with PIN
        elseif ($action === "unfreeze_card") {
            $pin = trim($_POST["unfreeze_pin"] ?? "");

            if (empty($user["card_pin_hash"])) {
                $message = "Please create a card PIN before unfreezing the card.";
                $messageType = "error";
            } elseif (!preg_match("/^[0-9]{4}$/", $pin)) {
                $message = "Please enter a valid 4-digit PIN.";
                $messageType = "error";
            } elseif (!password_verify($pin, $user["card_pin_hash"])) {
                $message = "Incorrect PIN. Card was not unfrozen.";
                $messageType = "error";

                logActivity($pdo, $userId, "Card Unfreeze Failed", "Incorrect PIN was used when trying to unfreeze the card.");
            } else {
                $stmt = $pdo->prepare("
                    UPDATE users
                    SET card_status = 'Active'
                    WHERE id = ?
                ");
                $stmt->execute([$userId]);

                logActivity($pdo, $userId, "Card Unfrozen", "User unfroze their card using the correct PIN.");

                $message = "Your card has been unfrozen.";
                $messageType = "success";
            }
        }

        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
        $user = getUser($pdo, $userId);
    }
}

$displayCardNumber = $showCardDetails ? $cardNumberFormatted : $maskedCardNumber;
$displayCvv = $showCardDetails ? $cvv : "•••";
$cardStatusClass = strtolower($user["card_status"]);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Cardiff Met Technology Bank</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>

<div class="app-shell">

    <div class="topbar">
        <div class="brand">
            <img src="../assets/cardiff-met-logo.png" class="brand-logo" alt="Cardiff Met Logo" onerror="this.style.display='none'">
            <div>
                <div class="brand-title">Cardiff Met Technology Bank</div>
                <div class="brand-subtitle">Secure digital banking prototype</div>
            </div>
        </div>

        <div class="nav-links">
            <a href="dashboard.php">Dashboard</a>
            <a href="transfer.php">Transfer</a>
            <a href="transactions.php">Transactions</a>
            <a href="logout.php">Logout</a>
        </div>
    </div>

    <div class="card">
        <h1>Welcome, <?php echo htmlspecialchars($user["full_name"]); ?></h1>
        <p>This is your secure online banking dashboard.</p>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo htmlspecialchars($messageType); ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <div class="dashboard-grid">
            <div class="balance-card">
                <div class="label">Current Balance</div>
                <div class="amount">£<?php echo number_format($user["balance"], 2); ?></div>
                <div>Protected by secure login, transaction checks, card controls, and fraud monitoring.</div>
            </div>

            <div class="account-card">
                <h2>Account Details</h2>

                <div class="account-row">
                    <strong>Username</strong>
                    <span><?php echo htmlspecialchars($user["username"]); ?></span>
                </div>

                <div class="account-row">
                    <strong>Sort Code</strong>
                    <span><?php echo htmlspecialchars($user["sort_code"]); ?></span>
                </div>

                <div class="account-row">
                    <strong>Account Number</strong>
                    <span><?php echo htmlspecialchars($user["account_number"]); ?></span>
                </div>
            </div>
        </div>

        <div class="bank-card-section">
            <h2>Your Card</h2>

            <div class="card-status-row">
                <span class="card-status <?php echo htmlspecialchars($cardStatusClass); ?>">
                    Card Status: <?php echo htmlspecialchars($user["card_status"]); ?>
                </span>
            </div>

            <div class="virtual-card <?php echo $user["card_status"] === "Frozen" ? "card-frozen" : ""; ?>">
                <div class="card-top">
                    <span>Cardiff Met Technology Bank</span>
                    <span><?php echo htmlspecialchars($cardType); ?></span>
                </div>

                <div class="chip-row">
                    <div class="chip"></div>
                    <div class="contactless">)))</div>
                </div>

                <div class="card-number">
                    <?php echo htmlspecialchars($displayCardNumber); ?>
                </div>

                <div class="card-bottom">
                    <div>
                        <small>Card Holder</small>
                        <strong><?php echo htmlspecialchars(strtoupper($user["full_name"])); ?></strong>
                    </div>

                    <div>
                        <small>Expires</small>
                        <strong><?php echo htmlspecialchars($expiryDate); ?></strong>
                    </div>

                    <div>
                        <small>CVV</small>
                        <strong><?php echo htmlspecialchars($displayCvv); ?></strong>
                    </div>
                </div>

                <?php if ($user["card_status"] === "Frozen"): ?>
                    <div class="frozen-overlay-text">CARD FROZEN</div>
                <?php endif; ?>
            </div>

            <div class="card-info-grid">
                <div class="card-info-box">
                    <span>Card Type</span>
                    <strong><?php echo htmlspecialchars($cardType); ?></strong>
                </div>

                <div class="card-info-box">
                    <span>Status</span>
                    <strong><?php echo htmlspecialchars($user["card_status"]); ?></strong>
                </div>

                <div class="card-info-box">
                    <span>Security</span>
                    <strong>PIN Protected</strong>
                </div>
            </div>

            <div class="card-controls">
                <?php if (empty($user["card_pin_hash"])): ?>
                    <div class="security-panel">
                        <h3>Create Card PIN</h3>
                        <p>Create a 4-digit PIN to unlock card details and unfreeze your card securely.</p>

                        <form method="POST" action="">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION["csrf_token"]); ?>">
                            <input type="hidden" name="action" value="set_pin">

                            <div class="form-group">
                                <label>New 4-digit PIN</label>
                                <input type="password" name="new_pin" maxlength="4" pattern="[0-9]{4}" required>
                            </div>

                            <div class="form-group">
                                <label>Confirm PIN</label>
                                <input type="password" name="confirm_pin" maxlength="4" pattern="[0-9]{4}" required>
                            </div>

                            <button type="submit" class="btn">Create PIN</button>
                        </form>
                    </div>
                <?php else: ?>
                    <div class="security-panel">
                        <h3>View Card Details</h3>
                        <p>Enter your 4-digit PIN to reveal the full card number and CVV.</p>

                        <form method="POST" action="">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION["csrf_token"]); ?>">
                            <input type="hidden" name="action" value="view_card">

                            <div class="form-group">
                                <label>Card PIN</label>
                                <input type="password" name="card_pin" maxlength="4" pattern="[0-9]{4}" required>
                            </div>

                            <button type="submit" class="btn">View Card Details</button>
                        </form>
                    </div>

                    <div class="security-panel">
                        <h3>Card Freeze Control</h3>

                        <?php if ($user["card_status"] === "Active"): ?>
                            <p>You can freeze your card if you notice suspicious activity.</p>

                            <form method="POST" action="">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION["csrf_token"]); ?>">
                                <input type="hidden" name="action" value="freeze_card">

                                <button type="submit" class="btn danger-btn">Freeze Card</button>
                            </form>
                        <?php else: ?>
                            <p>Your card is frozen. Enter your PIN to unfreeze it.</p>

                            <form method="POST" action="">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION["csrf_token"]); ?>">
                                <input type="hidden" name="action" value="unfreeze_card">

                                <div class="form-group">
                                    <label>Card PIN</label>
                                    <input type="password" name="unfreeze_pin" maxlength="4" pattern="[0-9]{4}" required>
                                </div>

                                <button type="submit" class="btn">Unfreeze Card</button>
                            </form>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="quick-actions">
            <a href="transfer.php" class="action-card">Make Transfer</a>
            <a href="transactions.php" class="action-card">Transaction History</a>
            <a href="logout.php" class="action-card">Logout</a>
        </div>
    </div>

</div>

</body>
</html>
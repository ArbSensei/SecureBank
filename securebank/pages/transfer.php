<?php
session_start();

require_once "../config/db.php";

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$message = "";
$messageType = "";
$userId = $_SESSION["user_id"];

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

function freezeCard($pdo, $userId) {
    $stmt = $pdo->prepare("
        UPDATE users
        SET card_status = 'Frozen'
        WHERE id = ?
    ");

    $stmt->execute([$userId]);
}

// Get logged-in user details
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);
$currentUser = $stmt->fetch();

if (!$currentUser) {
    session_destroy();
    header("Location: login.php");
    exit;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $receiverSortCodeInput = trim($_POST["receiver_sort_code"] ?? "");
    $receiverAccountInput = trim($_POST["receiver_account"] ?? "");
    $paymentReference = trim($_POST["payment_reference"] ?? "");
    $amountInput = trim($_POST["amount"] ?? "");
    $csrfToken = $_POST["csrf_token"] ?? "";

    // Allow sort code with or without dashes
    $receiverSortDigits = preg_replace("/\D/", "", $receiverSortCodeInput);
    $receiverSortCode = "";

    if (strlen($receiverSortDigits) === 6) {
        $receiverSortCode = substr($receiverSortDigits, 0, 2) . "-" . substr($receiverSortDigits, 2, 2) . "-" . substr($receiverSortDigits, 4, 2);
    }

    // Allow account number with or without spaces
    $receiverAccount = preg_replace("/\D/", "", $receiverAccountInput);

    // Scam warning answers
    $knowPerson = $_POST["know_person"] ?? "";
    $forcedPayment = $_POST["forced_payment"] ?? "";
    $couldBeScam = $_POST["could_be_scam"] ?? "";

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $message = "Invalid form request. Please try again.";
        $messageType = "error";
    }
    elseif ($currentUser["card_status"] === "Frozen") {
        $message = "Your card is frozen. Please unfreeze your card before making a transfer.";
        $messageType = "warning";

        logActivity($pdo, $userId, "Transfer Blocked", "Transfer was blocked because the card is frozen.");
    }
    elseif (empty($receiverSortCodeInput) || empty($receiverAccountInput) || empty($paymentReference) || empty($amountInput)) {
        $message = "Please fill in all fields, including the payment reference.";
        $messageType = "error";
    }
    elseif (!preg_match("/^[0-9]{6}$/", $receiverSortDigits)) {
        $message = "Invalid sort code. Please enter 6 digits, for example 202601 or 20-26-01.";
        $messageType = "error";
    }
    elseif (!preg_match("/^[0-9]{8}$/", $receiverAccount)) {
        $message = "Invalid account number. The account number must be 8 digits.";
        $messageType = "error";
    }
    elseif (!preg_match("/^[a-zA-Z0-9\s\-_]{2,100}$/", $paymentReference)) {
        $message = "Payment reference must be 2-100 characters and only use letters, numbers, spaces, hyphens or underscores.";
        $messageType = "error";
    }
    elseif (!is_numeric($amountInput) || $amountInput <= 0) {
        $message = "Please enter a valid transfer amount.";
        $messageType = "error";
    }
    elseif (
        $receiverAccount === $currentUser["account_number"] &&
        $receiverSortCode === $currentUser["sort_code"]
    ) {
        $message = "You cannot transfer money to your own account.";
        $messageType = "error";
    }
    elseif ($knowPerson !== "yes" || $forcedPayment !== "no" || $couldBeScam !== "no") {
        freezeCard($pdo, $userId);

        $message = "Transaction blocked and card frozen. Your scam warning answers showed a possible scam risk.";
        $messageType = "warning";

        logActivity($pdo, $userId, "Transfer Blocked", "Transfer blocked because scam warning answers showed possible scam risk.");
        logActivity($pdo, $userId, "Card Frozen", "Card was automatically frozen after scam risk was detected.");

        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $currentUser = $stmt->fetch();
    }
    else {
        $amount = (float)$amountInput;

        try {
            $pdo->beginTransaction();

            // Lock sender row during update
            $senderStmt = $pdo->prepare("SELECT * FROM users WHERE id = ? FOR UPDATE");
            $senderStmt->execute([$userId]);
            $sender = $senderStmt->fetch();

            // Check receiver using sort code and account number
            $receiverStmt = $pdo->prepare("
                SELECT * FROM users 
                WHERE account_number = ? AND sort_code = ?
                FOR UPDATE
            ");
            $receiverStmt->execute([$receiverAccount, $receiverSortCode]);
            $receiver = $receiverStmt->fetch();

            if (!$receiver) {
                $pdo->rollBack();

                $message = "Receiver account does not exist. Please check the sort code and account number.";
                $messageType = "error";

                logActivity($pdo, $userId, "Transfer Failed", "Transfer failed because receiver account does not exist.");
            }
            elseif ($amount > $sender["balance"]) {
                $pdo->rollBack();

                $message = "Transfer failed. You do not have enough balance.";
                $messageType = "error";

                logActivity($pdo, $userId, "Transfer Failed", "Transfer failed due to insufficient balance.");
            }
            elseif ($amount >= 500) {
                // Suspicious transfer is blocked and card is frozen
                $fraudScore = "Suspicious";

                $transactionStmt = $pdo->prepare("
                    INSERT INTO transactions 
                    (sender_id, receiver_account, receiver_sort_code, payment_reference, amount, status, fraud_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ");

                $transactionStmt->execute([
                    $sender["id"],
                    $receiverAccount,
                    $receiverSortCode,
                    $paymentReference,
                    $amount,
                    "Blocked",
                    $fraudScore
                ]);

                $freezeStmt = $pdo->prepare("
                    UPDATE users
                    SET card_status = 'Frozen'
                    WHERE id = ?
                ");
                $freezeStmt->execute([$sender["id"]]);

                logActivity($pdo, $userId, "Suspicious Transfer", "Suspicious transfer of £" . number_format($amount, 2) . " was blocked.");
                logActivity($pdo, $userId, "Card Frozen", "Card was automatically frozen after suspicious transfer activity.");

                $pdo->commit();

                $message = "Suspicious transfer blocked. Your card has been automatically frozen for your safety.";
                $messageType = "warning";

                $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                $stmt->execute([$userId]);
                $currentUser = $stmt->fetch();

                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            }
            else {
                $fraudScore = "Normal";

                // Update sender balance
                $newSenderBalance = $sender["balance"] - $amount;

                $updateSender = $pdo->prepare("
                    UPDATE users
                    SET balance = ?
                    WHERE id = ?
                ");
                $updateSender->execute([$newSenderBalance, $sender["id"]]);

                // Update receiver balance
                $newReceiverBalance = $receiver["balance"] + $amount;

                $updateReceiver = $pdo->prepare("
                    UPDATE users
                    SET balance = ?
                    WHERE id = ?
                ");
                $updateReceiver->execute([$newReceiverBalance, $receiver["id"]]);

                // Save transaction
                $transactionStmt = $pdo->prepare("
                    INSERT INTO transactions 
                    (sender_id, receiver_account, receiver_sort_code, payment_reference, amount, status, fraud_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ");

                $transactionStmt->execute([
                    $sender["id"],
                    $receiverAccount,
                    $receiverSortCode,
                    $paymentReference,
                    $amount,
                    "Completed",
                    $fraudScore
                ]);

                logActivity(
                    $pdo,
                    $userId,
                    "Transfer Completed",
                    "Transfer of £" . number_format($amount, 2) . " was completed. Reference: " . $paymentReference
                );

                $pdo->commit();

                $message = "Transfer completed successfully. Fraud status: " . $fraudScore;
                $messageType = "success";

                // Refresh current user details
                $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
                $stmt->execute([$userId]);
                $currentUser = $stmt->fetch();

                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            }

        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            $message = "Something went wrong. Please check that receiver_sort_code, payment_reference, card_status and card_pin_hash exist in the database.";
            $messageType = "error";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Make Transfer - Cardiff Met Technology Bank</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>

<div class="container">
    <div class="card">
        <img src="../assets/cardiff-met-logo.png" class="brand-logo" alt="Cardiff Met Logo" onerror="this.style.display='none'">

        <h1>Make a Transfer</h1>

        <p><strong>Your Sort Code:</strong> <?php echo htmlspecialchars($currentUser["sort_code"]); ?></p>
        <p><strong>Your Account Number:</strong> <?php echo htmlspecialchars($currentUser["account_number"]); ?></p>
        <p><strong>Your Balance:</strong> £<?php echo number_format($currentUser["balance"], 2); ?></p>
        <p><strong>Card Status:</strong> <?php echo htmlspecialchars($currentUser["card_status"]); ?></p>

        <?php if (!empty($message)): ?>
            <div class="message <?php echo htmlspecialchars($messageType); ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="" id="transferForm">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <input type="hidden" name="know_person" id="know_person">
            <input type="hidden" name="forced_payment" id="forced_payment">
            <input type="hidden" name="could_be_scam" id="could_be_scam">

            <div class="form-group">
                <label>Receiver Sort Code</label>
                <input type="text" name="receiver_sort_code" placeholder="Example: 20-26-01 or 202601" required>
            </div>

            <div class="form-group">
                <label>Receiver Account Number</label>
                <input type="text" name="receiver_account" placeholder="Example: 41475912" required>
            </div>

            <div class="form-group">
                <label>Payment Reference</label>
                <input type="text" name="payment_reference" placeholder="Example: Rent, Food, Invoice 123" maxlength="100" required>
            </div>

            <div class="form-group">
                <label>Amount (£)</label>
                <input type="number" name="amount" step="0.01" min="0.01" required>
            </div>

            <button type="button" class="btn" onclick="openScamModal()">Send Transfer</button>
            <a href="dashboard.php" class="btn secondary">Back Dashboard</a>
        </form>
    </div>
</div>

<!-- Scam Warning Modal -->
<div id="scamModal" class="modal-overlay">
    <div class="scam-modal">
        <h2>Scam Warning Check</h2>

        <div class="amber-warning">
            Before sending money, please answer these questions honestly.
            This check is designed to protect you from fraud and payment scams.
        </div>

        <div id="scamError" class="message error" style="display:none;">
            Transaction blocked. Your answers show a possible scam risk.
        </div>

        <div class="scam-question">
            <p><strong>1. Do you know the person you are sending money to?</strong></p>
            <label><input type="radio" name="q1" value="yes"> Yes</label>
            <label><input type="radio" name="q1" value="no"> No</label>
        </div>

        <div class="scam-question">
            <p><strong>2. Were you forced to send this money?</strong></p>
            <label><input type="radio" name="q2" value="yes"> Yes</label>
            <label><input type="radio" name="q2" value="no"> No</label>
        </div>

        <div class="scam-question">
            <p><strong>3. Could this be a scam?</strong></p>
            <label><input type="radio" name="q3" value="yes"> Yes</label>
            <label><input type="radio" name="q3" value="no"> No</label>
        </div>

        <div class="button-group">
            <button type="button" class="btn" onclick="confirmScamCheck()">Confirm and Send</button>
            <button type="button" class="btn secondary" onclick="closeScamModal()">Cancel</button>
        </div>
    </div>
</div>

<script>
function openScamModal() {
    document.getElementById("scamModal").style.display = "flex";
    document.getElementById("scamError").style.display = "none";
}

function closeScamModal() {
    document.getElementById("scamModal").style.display = "none";
}

function getSelectedValue(questionName) {
    let selected = document.querySelector('input[name="' + questionName + '"]:checked');
    return selected ? selected.value : "";
}

function confirmScamCheck() {
    let q1 = getSelectedValue("q1");
    let q2 = getSelectedValue("q2");
    let q3 = getSelectedValue("q3");

    if (q1 === "" || q2 === "" || q3 === "") {
        document.getElementById("scamError").innerText = "Please answer all scam warning questions before continuing.";
        document.getElementById("scamError").style.display = "block";
        return;
    }

    if (q1 !== "yes" || q2 !== "no" || q3 !== "no") {
        document.getElementById("scamError").innerText = "Transaction blocked. Your answers show a possible scam risk.";
        document.getElementById("scamError").style.display = "block";
        return;
    }

    document.getElementById("know_person").value = q1;
    document.getElementById("forced_payment").value = q2;
    document.getElementById("could_be_scam").value = q3;

    document.getElementById("transferForm").submit();
}
</script>

</body>
</html>
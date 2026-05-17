<?php
session_start();

require_once "../config/db.php";

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$userId = $_SESSION["user_id"];

// Get logged-in user
$userStmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$userStmt->execute([$userId]);
$currentUser = $userStmt->fetch();

if (!$currentUser) {
    session_destroy();
    header("Location: login.php");
    exit;
}

// Get transactions where the user is sender or receiver
$stmt = $pdo->prepare("
    SELECT 
        transactions.id,
        transactions.sender_id,
        transactions.receiver_account,
        transactions.amount,
        transactions.status,
        transactions.fraud_score,
        transactions.created_at,
        users.username AS sender_username,
        users.account_number AS sender_account
    FROM transactions
    LEFT JOIN users ON transactions.sender_id = users.id
    WHERE transactions.sender_id = ?
       OR transactions.receiver_account = ?
    ORDER BY transactions.created_at DESC
");

$stmt->execute([$userId, $currentUser["account_number"]]);
$transactions = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Transaction History - SecureBank</title>
    <link rel="stylesheet" href="../assets/style.css">
</head>
<body>

<div class="container">
    <div class="card">
        <h1>Transaction History</h1>

        <p><strong>Account Number:</strong> <?php echo htmlspecialchars($currentUser["account_number"]); ?></p>
        <p><strong>Current Balance:</strong> £<?php echo number_format($currentUser["balance"], 2); ?></p>

        <?php if (empty($transactions)): ?>
            <p>No transactions found.</p>
        <?php else: ?>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Type</th>
                            <th>Other Account</th>
                            <th>Amount</th>
                            <th>Status</th>
                            <th>Fraud Status</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($transactions as $transaction): ?>
                            <?php
                                $isSent = $transaction["sender_id"] == $userId;

                                if ($isSent) {
                                    $type = "Sent";
                                    $otherAccount = $transaction["receiver_account"];
                                } else {
                                    $type = "Received";
                                    $otherAccount = $transaction["sender_account"];
                                }

                                $fraudClass = strtolower($transaction["fraud_score"]);
                            ?>

                            <tr>
                                <td><?php echo htmlspecialchars($transaction["id"]); ?></td>
                                <td><?php echo htmlspecialchars($type); ?></td>
                                <td><?php echo htmlspecialchars($otherAccount); ?></td>
                                <td>£<?php echo number_format($transaction["amount"], 2); ?></td>
                                <td><?php echo htmlspecialchars($transaction["status"]); ?></td>
                                <td>
                                    <span class="badge <?php echo htmlspecialchars($fraudClass); ?>">
                                        <?php echo htmlspecialchars($transaction["fraud_score"]); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($transaction["created_at"]); ?></td>
                            </tr>

                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <div class="button-group">
            <a href="transfer.php" class="btn">Make Transfer</a>
            <a href="dashboard.php" class="btn secondary">Back Dashboard</a>
        </div>
    </div>
</div>

</body>
</html>
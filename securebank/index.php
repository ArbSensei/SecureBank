<?php
session_start();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cardiff Met Technology Bank</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>

<div class="container">
    <div class="hero-card">
        <img src="assets/cardiff-met-logo.png" class="brand-logo" alt="Cardiff Met Logo" onerror="this.style.display='none'">

        <h1>Cardiff Met Technology Bank</h1>

        <p>
            A secure online banking prototype created for the SEC5001 Secure Systems and Products assignment.
            This prototype demonstrates secure login, account protection, transaction validation, activity logging,
            and fraud detection.
        </p>

        <div class="button-group">
            <a href="pages/register.php" class="btn">Create Account</a>
            <a href="pages/login.php" class="btn secondary">Login</a>
        </div>
    </div>
</div>

</body>
</html>
<?php
session_start();
require_once __DIR__ . '/dotenv.php';

// Database Configuration
$host = $_ENV['DB_HOST'] ?? 'localhost';
$user = $_ENV['DB_USER'] ?? 'root';
$pass = $_ENV['DB_PASS'] ?? '';
$dbName = $_ENV['DB_NAME'] ?? 'backend';

// Handle JSON POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);
    
    $username = trim($input['username'] ?? '');
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'];

    try {
        $dsn = "mysql:host=$host;dbname=$dbName;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);

        // --- PROTECTION 1: Rate Limiting (Brute Force/Spam Prevention) ---
        // Limits an IP to 3 registration attempts every 5 minutes
        $stmtLimit = $pdo->prepare("SELECT COUNT(*) FROM rate_limits WHERE ip_address = ? AND attempt_time > NOW() - INTERVAL 5 MINUTE");
        $stmtLimit->execute([$ip]);
        if ($stmtLimit->fetchColumn() >= 3) {
            http_response_code(429);
            echo json_encode(['error' => 'Too many attempts. Please try again in 5 minutes.']);
            exit;
        }
        // Log the attempt
        $pdo->prepare("INSERT INTO rate_limits (ip_address) VALUES (?)")->execute([$ip]);

        // --- PROTECTION 2: Robust Password Policy ---
        // Requirements: 12+ chars, 1 Uppercase, 1 Number, 1 Special Character
        $passwordRegex = '/^(?=.*[A-Z])(?=.*[0-9])(?=.*[\W_]).{12,}$/';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match($passwordRegex, $password) || empty($username)) {
            echo json_encode(['error' => 'Invalid data. Password must be 12+ characters with a number and symbol.']);
            exit;
        }

        // --- PROTECTION 3: Check for Existing User ---
        $stmtCheck = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmtCheck->execute([$email]);
        if ($stmtCheck->fetch()) {
            echo json_encode(['error' => 'This email is already registered.']);
            exit;
        }

        // --- PROTECTION 4: Secure Hashing ---
        $hashedPassword = password_hash($password, PASSWORD_ARGON2ID);

        $stmt = $pdo->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')");
        if ($stmt->execute([$username, $email, $hashedPassword])) {
            echo json_encode(['success' => true, 'message' => 'Registration successful!']);
        }
        exit;

    } catch (PDOException $e) {
        error_log("Security Error: " . $e->getMessage());
        echo json_encode(['error' => 'A server error occurred. Please try again later.']);
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S'inscrire</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f8ff; }
        .register-container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; border-top: 5px solid #28a745; }
        h1 { text-align: center; color: #333; }
        input { width: 100%; padding: 0.5rem; margin: 0.5rem 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 0.5rem; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 1rem; }
        .error { color: red; text-align: center; }
        .success { color: green; text-align: center; }
        .login-link { text-align: center; margin-top: 1rem; display: block; color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="register-container">
        <h1>S'inscrire</h1>
        <small>Votre mot de passe doit comporter au moins 12 caractères avec un caractère spécial</small>
        <?php 
            if (isset($error)) echo "<p class='error'>$error</p>"; 
            if (isset($success)) echo "<p class='success'>$success</p>";
        ?>
        <form method="POST">
            <input type="text" name="username" placeholder="Nom d'utilisateur" required>
            <input type="email" name="email" placeholder="E-mail" required>
            <input type="text" name="password" placeholder="Mot de passe" required>
            <button type="submit">S'inscrire</button>
        </form>
        <a href="login.php" class="login-link">Déjà un compte ? Se connecter ici</a>
    </div>
</body>
</html>

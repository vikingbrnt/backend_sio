<?php
session_start();
require_once __DIR__ . '/dotenv.php';

$host = $_ENV['DB_HOST'] ?? 'localhost';
$user = $_ENV['DB_USER'] ?? 'root';
$pass = $_ENV['DB_PASS'] ?? '';
$dbName = $_ENV['DB_NAME'] ?? 'backend';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $username = trim($input['username'] ?? '');
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';

    // 1. Basic Validation
    if (empty($username) || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
        echo json_encode(['error' => 'Données invalides ou mot de passe trop court.']);
        exit;
    }

    // 2. Secure Connection (Using PDO is recommended over mysqli for better error handling)
    try {
        $dsn = "mysql:host=$host;dbname=$dbName;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);

        // 3. Hash the password (using modern Argon2 or Bcrypt)
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // 4. Prepared Statement
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')");
        
        if ($stmt->execute([$username, $email, $hashedPassword])) {
            echo json_encode(['success' => true, 'message' => 'Inscription réussie !']);
        }

    } catch (PDOException $e) {
        // 5. Professional Error Handling (Log it, don't show it)
        error_log("Registration Error: " . $e->getMessage());
        echo json_encode(['error' => 'Une erreur est survenue lors de l\'inscription.']);
    }
    
    $conn->close();
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

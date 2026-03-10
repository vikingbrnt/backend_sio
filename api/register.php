<?php
require_once __DIR__ . '/../dotenv.php';

header('Content-Type: application/json');
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit;
}

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
}
?>

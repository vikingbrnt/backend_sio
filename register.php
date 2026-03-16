<?php
session_start(); // Starts a new session or resumes the existing one to track user state
require_once __DIR__ . '/dotenv.php'; // Includes the environment file to load sensitive credentials like DB_PASS

// Database Configuration
$host = $_ENV['DB_HOST'] ?? 'localhost'; // Sets database host from environment variable or defaults to localhost
$user = $_ENV['DB_USER'] ?? 'root'; // Sets database username from environment or defaults to root
$pass = $_ENV['DB_PASS'] ?? ''; // Sets database password from environment or defaults to an empty string
$dbName = $_ENV['DB_NAME'] ?? 'backend'; // Sets the target database name from environment or defaults to backend

// Handle JSON POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') { // Only executes the following code if the request type is POST
    header('Content-Type: application/json'); // Tells the browser to expect a response in JSON format
    $input = json_decode(file_get_contents('php://input'), true); // Reads raw JSON input and converts it to a PHP array
    
    $username = trim($input['username'] ?? ''); // Gets username from input and removes extra spaces
    $email = trim($input['email'] ?? ''); // Gets email from input and removes extra spaces
    $password = $input['password'] ?? ''; // Gets password from input (no trim to preserve user's intended spaces)
    $ip = $_SERVER['REMOTE_ADDR']; // Captures the user's IP address to track who is sending the request

    try { // Starts a try block to catch any database errors that might occur
        $dsn = "mysql:host=$host;dbname=$dbName;charset=utf8mb4"; // Defines the Data Source Name string for the connection
        $pdo = new PDO($dsn, $user, $pass, [ // Attempts to create a new database connection object
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION // Configures PDO to throw exceptions if a query fails
        ]); // Ends the PDO constructor call

        // --- PROTECTION 1: Rate Limiting ---
        $stmtLimit = $pdo->prepare("SELECT COUNT(*) FROM rate_limits WHERE ip_address = ? AND attempt_time > NOW() - INTERVAL 5 MINUTE"); // Prepares query to count attempts from this IP
        $stmtLimit->execute([$ip]); // Executes the query using the captured IP address
        if ($stmtLimit->fetchColumn() >= 3) { // Checks if the count of attempts is 3 or higher
            http_response_code(429); // Sets HTTP status to 429 (Too Many Requests)
            echo json_encode(['error' => 'Too many attempts. Please try again in 5 minutes.']); // Sends error message as JSON
            exit; // Stops the script immediately to prevent further processing
        }
        
        // Log the attempt
        $pdo->prepare("INSERT INTO rate_limits (ip_address) VALUES (?)")->execute([$ip]); // Records this specific attempt in the rate_limits table

        // --- PROTECTION 2: Robust Password Policy ---
        $passwordRegex = '/^(?=.*[A-Z])(?=.*[0-9])(?=.*[\W_]).{12,}$/'; // Define regex for 12+ chars, 1 uppercase, 1 number, 1 symbol
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match($passwordRegex, $password) || empty($username)) { // Validates all inputs at once
            echo json_encode(['error' => 'Invalid data. Password must be 12+ characters with a number and symbol.']); // Sends validation error
            exit; // Stops the script if validation fails
        }

        // --- PROTECTION 3: Check for Existing User ---
        $stmtCheck = $pdo->prepare("SELECT id FROM users WHERE email = ?"); // Prepares query to find if the email is already in the database
        $stmtCheck->execute([$email]); // Executes the check using the user's provided email
        if ($stmtCheck->fetch()) { // If the query returns a result, the email is already taken
            echo json_encode(['error' => 'This email is already registered.']); // Sends error saying email exists
            exit;
        }

        // --- PROTECTION 4: Secure Hashing ---
        $hashedPassword = password_hash($password, PASSWORD_ARGON2ID); // Scrambles the password using a high-security algorithm

        $stmt = $pdo->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')"); // Prepares final insertion query
        if ($stmt->execute([$username, $email, $hashedPassword])) { // Executes insertion with the hashed password instead of plain text
            echo json_encode(['success' => true, 'message' => 'Registration successful!']); // Sends success response as JSON
        } // Ends the insertion success block
        exit;

    } catch (PDOException $e) { // If anything inside the "try" failed, this block catches the error
        error_log("Security Error: " . $e->getMessage()); // Logs the technical error message privately on the server
        echo json_encode(['error' => 'A server error occurred. Please try again later.']); // Sends a generic error message to the user
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

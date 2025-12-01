<?php
global $conn;
header('Content-Type: application/json');
require_once 'config/database.php'; // Your MySQLi connection ($conn)

$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

// Validate input
if(empty($email) || empty($password)){
    echo json_encode(['success' => false, 'message' => 'Both fields are required.']);
    exit;
}

// Prepare statement to prevent SQL injection
$stmt = $conn->prepare("SELECT id, email, password FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if($user && password_verify($password, $user['password'])){
    session_start();
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['email'] = $user['email'];
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid email or password.']);
}

$stmt->close();
$conn->close();
?>

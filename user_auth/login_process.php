<?php
global $conn;
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Content-Type: application/json');
require_once '../config/database.php'; // Adjust path relative to this file

$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

// Validate input
if(empty($email) || empty($password)){
    echo json_encode(['success' => false, 'message' => 'Both fields are required.']);
    exit;
}

//Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Invalid email format.']);
    exit;
}


//Ensure it is institutional email
$allowed_domain = '@lspu.edu.ph';
if (substr($email, -strlen($allowed_domain)) !== $allowed_domain) {
    echo json_encode(['success' => false, 'message' => 'Only institutional emails are allowed.']);
    exit;
}

// Prepare statement to prevent SQL injection
$stmt = $conn->prepare("SELECT id, email, password FROM users WHERE email = ?");
if(!$stmt){
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $conn->error]);
    exit;
}

$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if(!$user){
   echo json_encode(['success' => false, 'message' => "Email doesn't exist."]);
   exit;
}

if($user){
    // If passwords are hashed in DB
    if(password_verify($password, $user['password'])){
        session_start();
        session_regenerate_id(true); // safer session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['email'] = $user['email'];
        echo json_encode(['success' => true]);
    }
    // Optional: plaintext password check for testing only
    elseif($password === $user['password']){
        session_start();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['email'] = $user['email'];
        echo json_encode(['success' => true]);
    }
    else{
        echo json_encode(['success' => false, 'message' => 'Invalid email or password.']);
    }
}

$stmt->close();
$conn->close();
?>

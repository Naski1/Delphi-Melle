<?php
    include 'db.php';

    // $request_method = $_SERVER['REQUEST_METHOD'];
    // $endpoint = explode('/', trim($_SERVER['REQUEST_URI'], '/'))[1];

    function handleRegister($pdo) { 
        $data = json_decode(file_get_contents('php://input'), true);
        $username = $data['username'];
        $password = password_hash($data['password'], PASSWORD_BCRYPT);
        $nama = $data['nama'];
        $alamat = $data['alamat'];
    
        // Periksa apakah username sudah ada
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM pengguna WHERE username = ?");
        $stmt->execute([$username]);
        $count = $stmt->fetchColumn();
    
        if ($count > 0) {
            echo json_encode(['message' => 'Username already exists']);
            return;
        }
    
        // Jika username belum ada, lanjutkan dengan insert
        $stmt = $pdo->prepare("INSERT INTO pengguna (username, password, nama, alamat) VALUES (?, ?, ?, ?)");
        if ($stmt->execute([$username, $password, $nama, $alamat])) {
            echo json_encode(['message' => 'Registration successful']);
        } else {
            echo json_encode(['message' => 'Registration failed']);
        }
    }
    
    function handleLogin($pdo) {
        $data = json_decode(file_get_contents('php://input'), true);
        $username = $data['username'];
        $password = $data['password'];
    
        $stmt = $pdo->prepare("SELECT * FROM pengguna WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
        if ($user && password_verify($password, $user['password'])) {
            $token = bin2hex(random_bytes(16));
            $expiry = date('Y-m-d H:i:s', strtotime('+1 day'));
    
            $updateStmt = $pdo->prepare("UPDATE pengguna SET token = ? WHERE id_pengguna = ?");
            $updateStmt->execute([$token, $user['id_pengguna']]);
    
            echo json_encode(['message' => 'Login successful', 'token' => $token]);
        } else {
            echo json_encode(['message' => 'Invalid credentials']);
        }
    }
    
    function handleLogout($pdo) {
        $headers = getallheaders();
        $token = $headers['Authorization'] ?? null;
    
        if ($token) {
            $stmt = $pdo->prepare("UPDATE pengguna SET token = NULL WHERE token = ?");
            $stmt->execute([$token]);
            echo json_encode(['message' => 'Logout successful']);
        } else {
            echo json_encode(['message' => 'No token provided']);
        }
    }
    
    function productList($pdo) {
        $stmt = $pdo->query("SELECT id_produk, nama_produk, harga, foto_produk FROM produk");
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode($products);   
    }
    
    function cartItem($pdo, $request_method) {
        switch ($request_method) {
            case 'GET':
                $token = getallheaders()['Authorization'] ?? null;
                $userId = validateToken($pdo, $token);
            
                if ($userId) {
                    $stmt = $pdo->prepare("
                        SELECT keranjang.id_keranjang, produk.nama_produk, produk.harga, keranjang.jumlah 
                        FROM keranjang 
                        JOIN produk ON keranjang.id_produk = produk.id_produk 
                        WHERE keranjang.id_pengguna = ? 
                    ");
                    $stmt->execute([$userId]);
                    $cartItems = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
                    echo json_encode($cartItems);
                } else {
                    echo json_encode(['message' => 'Unauthorized']);
                }

                break;

                case 'POST':
                    $data = json_decode(file_get_contents('php://input'), true);
                    $token = getallheaders()['Authorization'] ?? null;
                    $userId = validateToken($pdo, $token);
                
                    if ($userId) {
                        $id_produk = $data['id_produk'];
                        $jumlah = $data['jumlah'];
                
                        // Periksa apakah id_produk sudah ada di tabel keranjang
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM keranjang WHERE id_pengguna = ? AND id_produk = ?");
                        $stmt->execute([$userId, $id_produk]);
                        $productExists = $stmt->fetchColumn() > 0;
                
                        if ($productExists) {
                            echo json_encode(['message' => 'Product already in cart']);
                        } else {
                            $stmt = $pdo->prepare("INSERT INTO keranjang (id_pengguna, id_produk, jumlah) VALUES (?, ?, ?)");
                            $stmt->execute([$userId, $id_produk, $jumlah]);
                
                            echo json_encode(['message' => 'Item added to cart']);
                        }
                    } else {
                        echo json_encode(['message' => 'Unauthorized']);
                    }
                
                    break;                
            
            case 'PUT':
                $data = json_decode(file_get_contents('php://input'), true);
                $token = getallheaders()['Authorization'] ?? null;
                $userId = validateToken($pdo, $token);
            
                if ($userId) {
                    $id_keranjang = $data['id_keranjang'];
                    $jumlah = $data['jumlah'];
            
                    $stmt = $pdo->prepare("UPDATE keranjang SET jumlah = ? WHERE id_keranjang = ? AND id_pengguna = ?");
                    $stmt->execute([$jumlah, $id_keranjang, $userId]);
            
                    echo json_encode(['message' => 'Cart updated']);
                } else {
                    echo json_encode(['message' => 'Unauthorized']);
                }

                break;
            
            case 'DELETE':
                $token = getallheaders()['Authorization'] ?? null;
                $userId = validateToken($pdo, $token);
            
                if ($userId) {
                    $id_keranjang = $_GET['id_keranjang'];
            
                    $stmt = $pdo->prepare("DELETE FROM keranjang WHERE id_keranjang = ? AND id_pengguna = ?");
                    $stmt->execute([$id_keranjang, $userId]);
            
                    echo json_encode(['message' => 'Item removed from cart']);
                } else {
                    echo json_encode(['message' => 'Unauthorized']);
                }

                break;
            
            default:
            echo json_encode(['message' => 'Invalid request method for cart']);
        } 
    }

    function userProfile($pdo, $request_method) {
        switch ($request_method) {
            case 'GET':
                $token = getallheaders()['Authorization'] ?? null;
                $userId = validateToken($pdo, $token);
            
                if ($userId) {
                    $stmt = $pdo->prepare("SELECT id_pengguna, username, nama, alamat FROM pengguna WHERE id_pengguna = ?");
                    $stmt->execute([$userId]);
                    $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
                    if ($user) {
                        echo json_encode($user);
                    } else {
                        echo json_encode(['message' => 'User not found']);
                    }
                } else {
                    echo json_encode(['message' => 'Unauthorized']);
                }

                break;

            case 'PUT':
                $token = getallheaders()['Authorization'] ?? null; 
                $userId = validateToken($pdo, $token);

                if ($userId) {
                    $data = json_decode(file_get_contents('php://input'), true);
                    $nama = $data['nama'] ?? '';
                    $alamat = $data['alamat'] ?? '';
                    $username = $data['username'] ?? '';
                    $currentPassword = $data['current_password'] ?? '';
                    $newPassword = $data['new_password'] ?? '';

                    if (!empty($username)) {
                        $stmt = $pdo->prepare("
                            SELECT id_pengguna 
                            FROM pengguna 
                            WHERE username = ? AND id_pengguna != ?
                        ");
                        $stmt->execute([$username, $userId]);
                        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

                        if ($existingUser) {
                            echo json_encode(['message' => 'Username already taken']);
                            return;
                        }
                    }

                    if (!empty($newPassword)) {
                        $stmt = $pdo->prepare("SELECT password FROM pengguna WHERE id_pengguna = ?");
                        $stmt->execute([$userId]);
                        $user = $stmt->fetch(PDO::FETCH_ASSOC);

                        if (!$user || !password_verify($currentPassword, $user['password'])) {
                            echo json_encode(['message' => 'Current password is incorrect']);
                            return;
                        }

                        $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
                    } else {
                        $hashedPassword = null;
                    }

                    $stmt = $pdo->prepare("
                        UPDATE pengguna 
                        SET 
                            nama = ?, 
                            alamat = ?, 
                            username = ?, 
                            password = IF(? IS NOT NULL, ?, password) 
                        WHERE id_pengguna = ?
                    ");
                    $stmt->execute([$nama, $alamat, $username, $hashedPassword, $hashedPassword, $userId]);

                    echo json_encode(['message' => 'Profile updated successfully']);
                } else {
                    echo json_encode(['message' => 'Unauthorized']);
                }

                break;

            default:
            echo json_encode(['message' => 'Invalid request method for user']);
        }
    }    
    
    function validateToken($pdo, $token) {
        $stmt = $pdo->prepare("SELECT id_pengguna FROM pengguna WHERE token = ?");
        $stmt->execute([$token]);
        $result = $stmt->fetchColumn();
        return $result;
    }
     
    $request_method = $_SERVER['REQUEST_METHOD'];
    $type = $_GET['type'] ?? ''; 

    header('Content-Type: application/json'); 

    if ($type === 'handleRegister') {
        handleRegister($pdo);
    } elseif ($type === 'handleLogin') {
        handleLogin($pdo);
    }elseif ($type === 'handleLogout') {
        handleLogout($pdo);   
    }elseif ($type === 'productList') {
        productList($pdo);   
    }elseif ($type === 'cartItem') {
        cartItem($pdo, $request_method);   
    }elseif ($type === 'userProfile') {
        userProfile($pdo, $request_method);   
    }else{
        echo json_encode(['message' => 'Invalid type parameter']);
    }

?>
        
<?php
/**
 * ==========================================================================
 * API Central para o Sistema Adriano.IO (CRM)
 * ==========================================================================
 * Este ficheiro funciona como um router e controlador central.
 * Ele recebe todas as requisições, verifica a autenticação,
 * interage com o banco de dados e retorna os dados em formato JSON.
 */

// Define o cabeçalho de resposta como JSON e permite requisições de qualquer origem (CORS)
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

// Responde a requisições OPTIONS (pre-flight) para CORS
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Inclui o ficheiro de configuração e a classe JWT
require_once 'config.php';
// A classe JWT pode ser mantida para futuras funcionalidades, como tokens de API para integrações externas.
class JWT { public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null) { $header = ['typ' => 'JWT', 'alg' => $alg]; if ($keyId !== null) { $header['kid'] = $keyId; } if (isset($head) && is_array($head)) { $header = array_merge($head, $header); } $segments = []; $segments[] = static::urlsafeB64Encode(json_encode($header)); $segments[] = static::urlsafeB64Encode(json_encode($payload)); $signing_input = implode('.', $segments); $signature = static::sign($signing_input, $key, $alg); $segments[] = static::urlsafeB64Encode($signature); return implode('.', $segments); } public static function decode($jwt, $key, array $allowed_algs = []) { $tks = explode('.', $jwt); if (count($tks) != 3) { throw new Exception('Wrong number of segments'); } list($headb64, $bodyb64, $cryptob64) = $tks; if (null === ($header = json_decode(static::urlsafeB64Decode($headb64), true))) { throw new Exception('Invalid header encoding'); } if (null === $payload = json_decode(static::urlsafeB64Decode($bodyb64), true))) { throw new Exception('Invalid claims encoding'); } $sig = static::urlsafeB64Decode($cryptob64); if (empty($header['alg']) || !in_array($header['alg'], $allowed_algs)) { throw new Exception('Algorithm not supported'); } if (!static::verify("$headb64.$bodyb64", $sig, $key, $header['alg'])) { throw new Exception('Signature verification failed'); } if (isset($payload['nbf']) && $payload['nbf'] > time()) { throw new Exception('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['nbf'])); } if (isset($payload['iat']) && $payload['iat'] > time()) { throw new Exception('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['iat'])); } if (isset($payload['exp']) && time() >= $payload['exp']) { throw new Exception('Expired token'); } return (object) $payload; } private static function verify($msg, $signature, $key, $alg) { if (empty(static::$supported_algs[$alg])) { throw new Exception('Algorithm not supported'); } list($function, $algorithm) = static::$supported_algs[$alg]; switch ($function) { case 'openssl': $success = openssl_verify($msg, $signature, $key, $algorithm); if ($success === 1) { return true; } if ($success === 0) { return false; } throw new Exception('OpenSSL error: ' . openssl_error_string()); case 'hash_hmac': default: $hash = hash_hmac($algorithm, $msg, $key, true); return hash_equals($signature, $hash); } } private static function sign($msg, $key, $alg = 'HS256') { if (empty(static::$supported_algs[$alg])) { throw new Exception('Algorithm not supported'); } list($function, $algorithm) = static::$supported_algs[$alg]; switch ($function) { case 'openssl': $signature = ''; $success = openssl_sign($msg, $signature, $key, $algorithm); if (!$success) { throw new Exception("OpenSSL unable to sign data"); } else { return $signature; } case 'hash_hmac': default: return hash_hmac($algorithm, $msg, $key, true); } } public static function urlsafeB64Decode($input) { $remainder = strlen($input) % 4; if ($remainder) { $padlen = 4 - $remainder; $input .= str_repeat('=', $padlen); } return base64_decode(strtr($input, '-_', '+/')); } public static function urlsafeB64Encode($input) { return str_replace('=', '', strtr(base64_encode($input), '+/', '-_')); } private static $supported_algs = [ 'HS256' => ['hash_hmac', 'sha256'], 'HS512' => ['hash_hmac', 'sha512'], 'HS384' => ['hash_hmac', 'sha384'], 'RS256' => ['openssl', 'sha256'], 'RS384' => ['openssl', 'sha384'], 'RS512' => ['openssl', 'sha512'], ];}

// Inicia a sessão para gestão de login
session_name(AUTH_SESSION_NAME);
session_start();

// --- Conexão com o Banco de Dados (PDO) ---
$pdo = null;
try {
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
} catch (\PDOException $e) {
    // Em caso de erro de conexão, termina a execução e retorna um erro 503
    http_response_code(503); // Service Unavailable
    echo json_encode(['status' => 'error', 'message' => 'Erro de conexão com o banco de dados: ' . $e->getMessage()]);
    exit;
}

// --- Funções Auxiliares ---
function json_response($data, $status_code = 200) {
    http_response_code($status_code);
    echo json_encode($data, JSON_NUMERIC_CHECK); // JSON_NUMERIC_CHECK para converter strings numéricas
    exit;
}

function get_input_data() {
    if (!empty($_POST)) { return $_POST; }
    return json_decode(file_get_contents('php://input'), true) ?: [];
}

function check_auth() {
    if (!isset($_SESSION['user_id'])) {
        json_response(['status' => 'error', 'message' => 'Acesso não autorizado. Por favor, faça login.'], 401);
    }
    return $_SESSION['user_id'];
}

/**
 * Função genérica para criar ou atualizar uma despesa recorrente de servidor.
 * Centraliza a lógica para evitar repetição de código.
 */
function handle_server_recurring_expense($pdo, $server_id, $server_name, $monthly_value, $is_client_server) {
    $source_id = "server-{$server_id}";
    $stmt_find = $pdo->prepare("SELECT id FROM recurring_transactions WHERE source_id = ?");
    $stmt_find->execute([$source_id]);
    $existing_recurring_id = $stmt_find->fetchColumn();

    // Se o servidor for de cliente ou não tiver custo, removemos a despesa recorrente se existir.
    if ($is_client_server || $monthly_value <= 0) {
        if ($existing_recurring_id) {
            $stmt_delete = $pdo->prepare("DELETE FROM recurring_transactions WHERE id = ?");
            $stmt_delete->execute([$existing_recurring_id]);
        }
    } 
    // Se for custo interno e tiver valor, criamos ou atualizamos a despesa.
    else {
        $params = [
            ':description' => "Custo Servidor: {$server_name}",
            ':value' => $monthly_value,
            ':source_id' => $source_id,
        ];
        if ($existing_recurring_id) {
            $params[':id'] = $existing_recurring_id;
            $stmt = $pdo->prepare("UPDATE recurring_transactions SET description = :description, value = :value WHERE id = :id");
        } else {
            $stmt = $pdo->prepare("INSERT INTO recurring_transactions (description, value, type, category, frequency, start_date, source_id) VALUES (:description, :value, 'Despesa', 'Infraestrutura', 'monthly', CURDATE(), :source_id)");
        }
        $stmt->execute($params);
    }
}


// --- Roteador Principal de Ações ---
$action = $_REQUEST['action'] ?? '';
$data = get_input_data();

switch ($action) {
    // #region AUTENTICAÇÃO
    case 'login':
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';
        $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_name'] = $user['name'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_role'] = $user['role'];
            unset($user['password_hash']);
            json_response(['status' => 'success', 'message' => 'Login bem-sucedido!', 'user' => $user]);
        } else {
            json_response(['status' => 'error', 'message' => 'Email ou senha inválidos.'], 401);
        }
        break;

    case 'logout':
        session_unset();
        session_destroy();
        json_response(['status' => 'success', 'message' => 'Logout bem-sucedido.']);
        break;
        
    case 'check_session':
        if(isset($_SESSION['user_id'])){
            json_response(['status' => 'success', 'user' => ['id' => $_SESSION['user_id'], 'name' => $_SESSION['user_name'], 'email' => $_SESSION['user_email'], 'role' => $_SESSION['user_role']]]);
        } else {
            json_response(['status' => 'error', 'message' => 'Sessão inválida ou expirada.'], 401);
        }
        break;
    // #endregion

    // #region DADOS INICIAIS
    case 'getInitialData':
        check_auth();
        try {
            $initial_data = [];
            $tables = ['clients', 'services', 'sales_funnel', 'projects', 'tasks', 'consulting_sessions', 'transactions', 'recurring_transactions', 'servers', 'hosted_services', 'channels', 'llm_api_keys', 'quick_links'];
            
            foreach ($tables as $table) {
                $stmt = $pdo->query("SELECT * FROM {$table}");
                $initial_data[$table] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }
            
            $initial_data['userInfo'] = ['id' => $_SESSION['user_id'], 'name' => $_SESSION['user_name'], 'email' => $_SESSION['user_email'], 'role' => $_SESSION['user_role']];
            json_response(['status' => 'success', 'data' => $initial_data]);
        } catch (PDOException $e) {
            json_response(['status' => 'error', 'message' => 'Erro ao buscar dados iniciais: ' . $e->getMessage()], 500);
        }
        break;
    // #endregion

    // #region CRUD Genérico (Requer um mapeamento cuidadoso no frontend)
    case 'create':
    case 'update':
    case 'delete':
        check_auth();
        $table = $data['table'] ?? '';
        $entity_data = $data['payload'] ?? [];
        $allowed_tables = ['clients', 'services', 'sales_funnel', 'projects', 'tasks', 'consulting_sessions', 'transactions', 'recurring_transactions', 'servers', 'hosted_services', 'channels', 'llm_api_keys', 'quick_links'];

        if (empty($table) || !in_array($table, $allowed_tables)) {
            json_response(['status' => 'error', 'message' => 'Tabela inválida ou não especificada.'], 400);
        }

        try {
            $pdo->beginTransaction();

            if ($action === 'create') {
                unset($entity_data['id']);
                $columns = implode(', ', array_keys($entity_data));
                $placeholders = ':' . implode(', :', array_keys($entity_data));
                $stmt = $pdo->prepare("INSERT INTO {$table} ({$columns}) VALUES ({$placeholders})");
                $stmt->execute($entity_data);
                $lastId = $pdo->lastInsertId();
                
                // Lógica de negócio específica pós-criação
                if($table === 'servers') {
                    handle_server_recurring_expense($pdo, $lastId, $entity_data['name'], $entity_data['monthly_value'], !empty($entity_data['client_id']));
                }

                json_response(['status' => 'success', 'message' => 'Item criado com sucesso!', 'id' => $lastId]);
            }
            elseif ($action === 'update') {
                $id = $entity_data['id'] ?? 0;
                if (!$id) json_response(['status' => 'error', 'message' => 'ID não fornecido para atualização.'], 400);
                
                unset($entity_data['id']);
                $set_parts = [];
                foreach ($entity_data as $key => $value) { $set_parts[] = "{$key} = :{$key}"; }
                $sql = "UPDATE {$table} SET " . implode(', ', $set_parts) . " WHERE id = :id";
                $entity_data['id'] = $id;

                $stmt = $pdo->prepare($sql);
                $stmt->execute($entity_data);
                
                // Lógica de negócio específica pós-atualização
                if($table === 'servers') {
                     handle_server_recurring_expense($pdo, $id, $entity_data['name'], $entity_data['monthly_value'], !empty($entity_data['client_id']));
                }
                if ($table === 'sales_funnel' && isset($entity_data['stage']) && $entity_data['stage'] === 'Fechado') {
                    $dealStmt = $pdo->prepare("SELECT * FROM sales_funnel WHERE id = ?");
                    $dealStmt->execute([$id]);
                    $deal = $dealStmt->fetch();
                    if ($deal) {
                        // Evitar duplicação de projeto
                        $projStmt = $pdo->prepare("SELECT COUNT(*) FROM projects WHERE title = ? AND client_id = ?");
                        $projStmt->execute([$deal['title'], $deal['client_id']]);
                        if($projStmt->fetchColumn() == 0) {
                            $deadline = date('Y-m-d', strtotime('+30 days'));
                            $pdo->prepare("INSERT INTO projects (client_id, service_id, title, budget, deadline, status) VALUES (?, ?, ?, ?, ?, 'A Fazer')")
                                ->execute([$deal['client_id'], $deal['service_id'], $deal['title'], $deal['value'], $deadline]);
                        }
                    }
                }

                json_response(['status' => 'success', 'message' => 'Item atualizado com sucesso!']);
            }
            elseif ($action === 'delete') {
                $id = $entity_data['id'] ?? 0;
                if (!$id) json_response(['status' => 'error', 'message' => 'ID não fornecido para exclusão.'], 400);

                // Lógica de negócio específica pré-exclusão
                 if($table === 'servers') {
                    handle_server_recurring_expense($pdo, $id, '', 0, true); // Simula ser de cliente para apagar a recorrência
                }

                $stmt = $pdo->prepare("DELETE FROM {$table} WHERE id = ?");
                $stmt->execute([$id]);
                json_response(['status' => 'success', 'message' => 'Item removido com sucesso!']);
            }

            $pdo->commit();

        } catch (PDOException $e) {
            $pdo->rollBack();
            json_response(['status' => 'error', 'message' => "Erro na operação com {$table}: " . $e->getMessage()], 500);
        }
        break;
    // #endregion

    default:
        json_response(['status' => 'error', 'message' => 'Ação desconhecida ou não especificada.'], 404);
        break;
}
?>

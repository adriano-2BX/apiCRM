<?php
/**
 * Ficheiro de Configuração da API
 *
 * Armazena as credenciais do banco de dados e outras constantes importantes.
 * É crucial manter este ficheiro seguro e fora do acesso público direto.
 */

// --- Configuração do Banco de Dados ---
define('DB_HOST', 'server.2bx.com.br');      // Host do seu servidor de banco de dados
define('DB_PORT', '3306');                  // Porta do servidor de banco de dados
define('DB_NAME', 'crm');                   // O nome do banco de dados
define('DB_USER', 'root');                  // O seu nome de utilizador do banco de dados
define('DB_PASS', 'd21d846891a08dfaa82b');   // A sua senha do banco de dados
define('DB_CHARSET', 'utf8mb4');            // Charset recomendado para compatibilidade total

// --- Configuração de Segurança ---
define('JWT_SECRET_KEY', 'd21d846891a08dfaa82b3c4d5e6f7g8h'); // Chave secreta para JWT (pode ser útil no futuro)

// --- Configuração de Sessão ---
define('AUTH_SESSION_NAME', 'adriano_crm_auth'); // Nome da sessão para o login

?>

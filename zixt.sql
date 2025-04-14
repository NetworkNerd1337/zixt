CREATE DATABASE zixt_db;
USE zixt_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    is_verified BOOLEAN DEFAULT 0,
    verification_token VARCHAR(255)
);

CREATE TABLE threads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    creator_id INT,
    FOREIGN KEY (creator_id) REFERENCES users(id)
);

CREATE TABLE thread_participants (
    id INT AUTO_INCREMENT PRIMARY KEY,
    thread_id INT,
    user_id INT,
    is_deleted BOOLEAN DEFAULT 0,
    FOREIGN KEY (thread_id) REFERENCES threads(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    thread_id INT,
    sender_id INT,
    ciphertext BLOB NOT NULL,
    kyber_ciphertext BLOB NOT NULL,
    kyber_public_key BLOB NOT NULL,
    file_path VARCHAR(255),
    FOREIGN KEY (thread_id) REFERENCES threads(id),
    FOREIGN KEY (sender_id) REFERENCES users(id)
);

CREATE TABLE encryption_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_value BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Create initial admin user
INSERT INTO users (username, email, password, is_admin, is_verified)
VALUES ('admin', 'admin@zixt.app', '$argon2id$v=19$m=32768,t=16,p=2$...', 1, 1);

CREATE USER 'zixt_user'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON zixt_db.* TO 'zixt_user'@'localhost';
FLUSH PRIVILEGES;
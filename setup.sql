CREATE DATABASE zixt_db;
CREATE USER 'zixt_user'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON zixt_db.* TO 'zixt_user'@'localhost';
FLUSH PRIVILEGES;

USE zixt_db;

CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(128),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_key_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE thread (
    id INT AUTO_INCREMENT PRIMARY KEY,
    creator_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    FOREIGN KEY (creator_id) REFERENCES user(id)
);

CREATE TABLE thread_participant (
    id INT AUTO_INCREMENT PRIMARY KEY,
    thread_id INT NOT NULL,
    user_id INT NOT NULL,
    deleted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (thread_id) REFERENCES thread(id),
    FOREIGN KEY (user_id) REFERENCES user(id),
    UNIQUE(thread_id, user_id)
);

CREATE TABLE message (
    id INT AUTO_INCREMENT PRIMARY KEY,
    thread_id INT NOT NULL,
    sender VARCHAR(80) NOT NULL,
    content TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    file_path VARCHAR(256),
    file_name VARCHAR(100),
    file_type VARCHAR(50),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (thread_id) REFERENCES thread(id)
);
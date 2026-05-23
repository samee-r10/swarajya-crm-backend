USE lms_crm;

ALTER TABLE app_users
    ADD COLUMN IF NOT EXISTS has_finance_access TINYINT(1) NOT NULL DEFAULT 0 AFTER has_treasury_access,
    ADD COLUMN IF NOT EXISTS has_vault_access TINYINT(1) NOT NULL DEFAULT 0 AFTER has_finance_access,
    ADD COLUMN IF NOT EXISTS vault_access_code_hash VARCHAR(255) AFTER has_vault_access;

CREATE TABLE IF NOT EXISTS vault_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(180) NOT NULL,
    category VARCHAR(80) NOT NULL DEFAULT 'Other',
    login_id VARCHAR(255),
    password_encrypted TEXT,
    notes TEXT,
    url VARCHAR(500),
    customer_id INT NULL,
    project_id INT NULL,
    created_by_id INT NULL,
    updated_by_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_vault_entries_category (category),
    INDEX idx_vault_entries_title (title),
    CONSTRAINT fk_vault_entries_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
    CONSTRAINT fk_vault_entries_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL,
    CONSTRAINT fk_vault_entries_created_by FOREIGN KEY (created_by_id) REFERENCES app_users(id) ON DELETE SET NULL,
    CONSTRAINT fk_vault_entries_updated_by FOREIGN KEY (updated_by_id) REFERENCES app_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS vault_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_vault_logs_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE
);

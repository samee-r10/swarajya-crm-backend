CREATE DATABASE IF NOT EXISTS lms_crm CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE lms_crm;

CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    company_name VARCHAR(160) NOT NULL,
    contact_name VARCHAR(120) NOT NULL,
    email VARCHAR(160),
    phone VARCHAR(40),
    industry VARCHAR(100),
    status ENUM('Lead', 'Active', 'Inactive') NOT NULL DEFAULT 'Lead',
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_customers_status (status)
);

CREATE TABLE IF NOT EXISTS opportunities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    country VARCHAR(100),
    title VARCHAR(180) NOT NULL,
    opportunity_number VARCHAR(100),
    value DECIMAL(12, 2) NOT NULL DEFAULT 0,
    stage VARCHAR(100) NOT NULL DEFAULT 'Draft',
    expected_close DATE,
    requirements TEXT,
    next_action VARCHAR(220),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_opportunities_stage (stage),
    CONSTRAINT fk_opportunities_customer
        FOREIGN KEY (customer_id) REFERENCES customers(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS projects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    opportunity_id INT NOT NULL,
    project_name VARCHAR(180) NOT NULL,
    status ENUM('Planning', 'In Progress', 'Blocked', 'Delivered', 'On Hold') NOT NULL DEFAULT 'Planning',
    client_requirements TEXT,
    delivery_timeline DATE,
    product_delivery_status VARCHAR(220),
    owner VARCHAR(120),
    last_update TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_projects_status (status),
    CONSTRAINT fk_projects_customer
        FOREIGN KEY (customer_id) REFERENCES customers(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_projects_opportunity
        FOREIGN KEY (opportunity_id) REFERENCES opportunities(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(120) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(140) NOT NULL,
    email VARCHAR(160) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    has_treasury_access TINYINT(1) NOT NULL DEFAULT 0,
    has_finance_access TINYINT(1) NOT NULL DEFAULT 0,
    has_vault_access TINYINT(1) NOT NULL DEFAULT 0,
    vault_access_code_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_app_users_role
        FOREIGN KEY (role_id) REFERENCES roles(id)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS custom_objects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    label VARCHAR(120) NOT NULL,
    plural_label VARCHAR(140) NOT NULL,
    api_name VARCHAR(120) NOT NULL UNIQUE,
    is_standard TINYINT(1) NOT NULL DEFAULT 0,
    storage_table VARCHAR(120),
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS custom_fields (
    id INT AUTO_INCREMENT PRIMARY KEY,
    object_id INT NOT NULL,
    label VARCHAR(120) NOT NULL,
    api_name VARCHAR(120) NOT NULL,
    is_native TINYINT(1) NOT NULL DEFAULT 0,
    native_column VARCHAR(120),
    field_type ENUM('Text', 'Long Text', 'Number', 'Date', 'Checkbox') NOT NULL DEFAULT 'Text',
    is_required TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_custom_fields_object_api (object_id, api_name),
    CONSTRAINT fk_custom_fields_object
        FOREIGN KEY (object_id) REFERENCES custom_objects(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS custom_object_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    object_id INT NOT NULL,
    name VARCHAR(180) NOT NULL,
    data JSON NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_custom_object_records_object (object_id),
    CONSTRAINT fk_custom_object_records_object
        FOREIGN KEY (object_id) REFERENCES custom_objects(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS field_level_security (
    role_id INT NOT NULL,
    field_id INT NOT NULL,
    can_view TINYINT(1) NOT NULL DEFAULT 1,
    can_edit TINYINT(1) NOT NULL DEFAULT 1,
    PRIMARY KEY (role_id, field_id),
    CONSTRAINT fk_fls_role
        FOREIGN KEY (role_id) REFERENCES roles(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_fls_field
        FOREIGN KEY (field_id) REFERENCES custom_fields(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS standard_field_values (
    field_id INT NOT NULL,
    record_id INT NOT NULL,
    value_json JSON NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (field_id, record_id),
    CONSTRAINT fk_standard_field_values_field
        FOREIGN KEY (field_id) REFERENCES custom_fields(id)
        ON DELETE CASCADE
);

INSERT IGNORE INTO roles (id, name, description)
VALUES (1, 'System Administrator', 'Full setup and object access.');

INSERT IGNORE INTO custom_objects (label, plural_label, api_name, is_standard, storage_table, description)
VALUES
    ('Customer', 'Customers', 'customers', 1, 'customers', 'Standard customer object.'),
    ('Opportunity', 'Opportunities', 'opportunities', 1, 'opportunities', 'Standard sales opportunity object.'),
    ('Project', 'Projects', 'projects', 1, 'projects', 'Standard delivery project object.');

INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Company Name', 'company_name', 1, 'company_name', 'Text', 1 FROM custom_objects WHERE api_name = 'customers';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Contact Name', 'contact_name', 1, 'contact_name', 'Text', 1 FROM custom_objects WHERE api_name = 'customers';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Email', 'email', 1, 'email', 'Text', 0 FROM custom_objects WHERE api_name = 'customers';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Phone', 'phone', 1, 'phone', 'Text', 0 FROM custom_objects WHERE api_name = 'customers';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Industry', 'industry', 1, 'industry', 'Text', 0 FROM custom_objects WHERE api_name = 'customers';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Status', 'status', 1, 'status', 'Text', 1 FROM custom_objects WHERE api_name = 'customers';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Notes', 'notes', 1, 'notes', 'Long Text', 0 FROM custom_objects WHERE api_name = 'customers';

INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Customer', 'customer_id', 1, 'customer_id', 'Number', 1 FROM custom_objects WHERE api_name = 'opportunities';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Title', 'title', 1, 'title', 'Text', 1 FROM custom_objects WHERE api_name = 'opportunities';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Value', 'value', 1, 'value', 'Number', 0 FROM custom_objects WHERE api_name = 'opportunities';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Stage', 'stage', 1, 'stage', 'Text', 1 FROM custom_objects WHERE api_name = 'opportunities';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Expected Close', 'expected_close', 1, 'expected_close', 'Date', 0 FROM custom_objects WHERE api_name = 'opportunities';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Requirements', 'requirements', 1, 'requirements', 'Long Text', 0 FROM custom_objects WHERE api_name = 'opportunities';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Next Action', 'next_action', 1, 'next_action', 'Text', 0 FROM custom_objects WHERE api_name = 'opportunities';

INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Customer', 'customer_id', 1, 'customer_id', 'Number', 1 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Opportunity', 'opportunity_id', 1, 'opportunity_id', 'Number', 1 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Project Name', 'project_name', 1, 'project_name', 'Text', 1 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Status', 'status', 1, 'status', 'Text', 1 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Client Requirements', 'client_requirements', 1, 'client_requirements', 'Long Text', 0 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Delivery Timeline', 'delivery_timeline', 1, 'delivery_timeline', 'Date', 0 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Product Delivery Status', 'product_delivery_status', 1, 'product_delivery_status', 'Text', 0 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Owner', 'owner', 1, 'owner', 'Text', 0 FROM custom_objects WHERE api_name = 'projects';
INSERT IGNORE INTO custom_fields (object_id, label, api_name, is_native, native_column, field_type, is_required)
SELECT id, 'Latest Update', 'last_update', 1, 'last_update', 'Long Text', 0 FROM custom_objects WHERE api_name = 'projects';

-- Treasury Management Tables
CREATE TABLE IF NOT EXISTS treasury_stakeholders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    payout_percentage DECIMAL(5, 2) NOT NULL,
    payment_details TEXT,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS treasury_channel_partners (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    commission_type ENUM('Percentage', 'Fixed') NOT NULL DEFAULT 'Percentage',
    commission_value DECIMAL(15, 2) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS treasury_revenue (
    id INT AUTO_INCREMENT PRIMARY KEY,
    revenue_id VARCHAR(50) NULL UNIQUE,
    amount DECIMAL(15, 2) NOT NULL,
    project_id INT NULL,
    revenue_type ENUM('Sales Income', 'Service Income', 'Other Income') NOT NULL,
    entry_date DATE NOT NULL,
    description TEXT,
    transaction_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_treasury_revenue_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL,
    CONSTRAINT fk_treasury_revenue_transaction FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS treasury_splits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    revenue_id INT NOT NULL,
    reserve_percentage DECIMAL(5, 2) NOT NULL DEFAULT 20.00,
    reserve_amount DECIMAL(15, 2) NOT NULL,
    channel_partner_id INT NULL,
    partner_commission DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
    stakeholder_total DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_treasury_splits_revenue FOREIGN KEY (revenue_id) REFERENCES treasury_revenue(id) ON DELETE CASCADE,
    CONSTRAINT fk_treasury_splits_partner FOREIGN KEY (channel_partner_id) REFERENCES treasury_channel_partners(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS treasury_payouts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    revenue_id INT NOT NULL,
    payout_type ENUM('Reserve Fund', 'Channel Partner', 'Stakeholder') NOT NULL,
    stakeholder_id INT NULL,
    channel_partner_id INT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    payout_date DATE NOT NULL,
    status ENUM('Pending', 'Paid') NOT NULL DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_treasury_payouts_revenue FOREIGN KEY (revenue_id) REFERENCES treasury_revenue(id) ON DELETE CASCADE,
    CONSTRAINT fk_treasury_payouts_stakeholder FOREIGN KEY (stakeholder_id) REFERENCES treasury_stakeholders(id) ON DELETE SET NULL,
    CONSTRAINT fk_treasury_payouts_partner FOREIGN KEY (channel_partner_id) REFERENCES treasury_channel_partners(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS treasury_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_treasury_logs_user FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE
);

-- Credential Vault Tables
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

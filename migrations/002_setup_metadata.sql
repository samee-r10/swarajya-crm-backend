USE lms_crm;

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

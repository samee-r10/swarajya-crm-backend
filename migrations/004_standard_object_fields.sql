USE lms_crm;

ALTER TABLE custom_objects
    ADD COLUMN is_standard TINYINT(1) NOT NULL DEFAULT 0 AFTER api_name,
    ADD COLUMN storage_table VARCHAR(120) NULL AFTER is_standard;

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

INSERT IGNORE INTO custom_objects (label, plural_label, api_name, is_standard, storage_table, description)
VALUES
    ('Customer', 'Customers', 'customers', 1, 'customers', 'Standard customer object.'),
    ('Opportunity', 'Opportunities', 'opportunities', 1, 'opportunities', 'Standard sales opportunity object.'),
    ('Project', 'Projects', 'projects', 1, 'projects', 'Standard delivery project object.');

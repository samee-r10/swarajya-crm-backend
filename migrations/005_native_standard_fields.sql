USE lms_crm;

ALTER TABLE custom_fields
    ADD COLUMN is_native TINYINT(1) NOT NULL DEFAULT 0 AFTER api_name,
    ADD COLUMN native_column VARCHAR(120) NULL AFTER is_native;

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

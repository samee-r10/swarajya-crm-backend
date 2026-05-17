USE lms_crm;

SELECT id, project_name
FROM projects
WHERE opportunity_id IS NULL;

ALTER TABLE projects
    MODIFY opportunity_id INT NOT NULL;

USE lms_crm;

ALTER TABLE app_users
    ADD COLUMN password_hash VARCHAR(255) NULL AFTER email;

UPDATE app_users
SET password_hash = 'pbkdf2:sha256:1000000$change-me$80c5f3203f777a8ef4e37c98c74267c39517e4870e9f5fe75299c6780cfa5d72'
WHERE password_hash IS NULL;

ALTER TABLE app_users
    MODIFY password_hash VARCHAR(255) NOT NULL;

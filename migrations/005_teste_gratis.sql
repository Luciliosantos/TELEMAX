ALTER TABLE bv_client_config
ADD COLUMN test_enabled INTEGER NOT NULL DEFAULT 1;

ALTER TABLE bv_client_config
ADD COLUMN test_duration_hours INTEGER NOT NULL DEFAULT 2;

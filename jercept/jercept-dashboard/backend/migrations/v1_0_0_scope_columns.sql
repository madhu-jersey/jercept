-- Jercept Dashboard v1.0.0 migration
-- Adds scope visualizer columns to security_events table
-- Run once when upgrading from any v0.x deployment

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS allowed_actions TEXT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS denied_actions TEXT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS allowed_resources TEXT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS extraction_tier VARCHAR(16);

-- Add channel type enum and column
CREATE TYPE channel_type AS ENUM ('text', 'voice');

ALTER TABLE channels
    ADD COLUMN type channel_type NOT NULL DEFAULT 'text';

-- Voice-specific settings (only relevant when type = 'voice')
ALTER TABLE channels
    ADD COLUMN bitrate    INTEGER,
    ADD COLUMN user_limit INTEGER;

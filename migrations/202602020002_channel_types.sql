-- Add channel type enum and column
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_type t
                                JOIN pg_namespace n ON n.oid = t.typnamespace
                       WHERE t.typname = 'channel_type'
                         AND n.nspname = 'public') THEN
            CREATE TYPE channel_type AS ENUM ('text', 'voice');
        END IF;
    END
$$;

ALTER TABLE channels
    ADD COLUMN IF NOT EXISTS type channel_type NOT NULL DEFAULT 'text';

-- Voice-specific settings (only relevant when type = 'voice')
ALTER TABLE channels
    ADD COLUMN IF NOT EXISTS bitrate    INTEGER,
    ADD COLUMN IF NOT EXISTS user_limit INTEGER;

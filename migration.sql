CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    started_at INTEGER DEFAULT 0,
    last_seen INTEGER,
    reports_count INTEGER DEFAULT 0,
    is_vip INTEGER DEFAULT 0,
    banned_until INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen);
CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned_until);

CREATE TABLE IF NOT EXISTS admins (user_id INTEGER PRIMARY KEY, added_at INTEGER DEFAULT (unixepoch()));
CREATE TABLE IF NOT EXISTS web_admins (username TEXT PRIMARY KEY, password_hash TEXT, created_at INTEGER DEFAULT (unixepoch()));

CREATE TABLE IF NOT EXISTS whispers (
    id TEXT PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    target_ids TEXT NOT NULL,
    target_usernames TEXT,
    text TEXT NOT NULL DEFAULT '',
    media_code TEXT,
    inline_message_id TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    viewed_by TEXT DEFAULT '[]',
    status TEXT DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_whispers_created ON whispers(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_whispers_status ON whispers(status);
CREATE INDEX IF NOT EXISTS idx_whispers_sender ON whispers(sender_id);
CREATE INDEX IF NOT EXISTS idx_whispers_media ON whispers(media_code);
CREATE INDEX IF NOT EXISTS idx_whispers_inline ON whispers(inline_message_id);

CREATE TABLE IF NOT EXISTS pending_whispers (
    token TEXT PRIMARY KEY,
    sender_id INTEGER,
    target_ids TEXT,
    target_usernames TEXT,
    text TEXT,
    media_code TEXT,
    created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_whispers(created_at);
CREATE INDEX IF NOT EXISTS idx_pending_sender ON pending_whispers(sender_id);

CREATE TABLE IF NOT EXISTS user_media (
    code TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    file_id TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_user_media_user ON user_media(user_id);
CREATE INDEX IF NOT EXISTS idx_user_media_created ON user_media(created_at);

CREATE TABLE IF NOT EXISTS peepers (
    whisper_id TEXT,
    user_id INTEGER,
    username TEXT,
    first_name TEXT,
    peeked_at INTEGER DEFAULT (unixepoch()),
    PRIMARY KEY (whisper_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_peepers_whisper ON peepers(whisper_id);
CREATE INDEX IF NOT EXISTS idx_peepers_user ON peepers(user_id);
CREATE INDEX IF NOT EXISTS idx_peepers_peeked ON peepers(peeked_at);

CREATE TABLE IF NOT EXISTS replies (
    id TEXT PRIMARY KEY,
    whisper_id TEXT,
    from_id INTEGER,
    to_id INTEGER,
    text TEXT,
    created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_replies_whisper ON replies(whisper_id);
CREATE INDEX IF NOT EXISTS idx_replies_from ON replies(from_id);
CREATE INDEX IF NOT EXISTS idx_replies_to ON replies(to_id);
CREATE INDEX IF NOT EXISTS idx_replies_created ON replies(created_at);

CREATE TABLE IF NOT EXISTS blocks (
    user_id INTEGER,
    blocked_id INTEGER,
    created_at INTEGER DEFAULT (unixepoch()),
    PRIMARY KEY (user_id, blocked_id)
);
CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_id);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    whisper_id TEXT,
    reporter_id INTEGER,
    reason TEXT,
    created_at INTEGER DEFAULT (unixepoch())
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_unique ON reports(whisper_id, reporter_id);
CREATE INDEX IF NOT EXISTS idx_reports_whisper ON reports(whisper_id);
CREATE INDEX IF NOT EXISTS idx_reports_reporter ON reports(reporter_id);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY,
    notifications INTEGER DEFAULT 1,
    lang TEXT DEFAULT 'fa',
    updated_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_user_settings_lang ON user_settings(lang);

CREATE TABLE IF NOT EXISTS processed_updates (
    update_id INTEGER PRIMARY KEY,
    status TEXT DEFAULT 'done',
    created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_processed_created ON processed_updates(created_at);
CREATE INDEX IF NOT EXISTS idx_processed_status ON processed_updates(status);

CREATE TABLE IF NOT EXISTS broadcasts (
    id TEXT PRIMARY KEY,
    text TEXT,
    sent_by INTEGER,
    sent_at INTEGER,
    recipients INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    cursor_offset INTEGER DEFAULT 0,
    total_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_broadcasts_status ON broadcasts(status);
CREATE INDEX IF NOT EXISTS idx_broadcasts_sent ON broadcasts(sent_at);

CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    ip TEXT,
    action TEXT,
    details TEXT,
    created_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_admin_logs_created ON admin_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_logs_admin ON admin_logs(admin_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    ip TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    updated_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_login_updated ON login_attempts(updated_at);
CREATE INDEX IF NOT EXISTS idx_login_locked ON login_attempts(locked_until);

CREATE TABLE IF NOT EXISTS sessions_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    user_agent TEXT,
    logged_in_at INTEGER DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_sessions_log_time ON sessions_log(logged_in_at DESC);

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('force_start', '0'), ('ads_enabled', '0'), ('maintenance_mode', '0'),
  ('ads_text', ''), ('ads_url', ''), ('ads_image_url', ''),
  ('whisper_ttl_days', '7'), ('max_whisper_length', '4000'),
  ('require_start_for_reply', '1'), ('announce_replies', '1'),
  ('default_theme', 'dark'), ('language', 'fa'),
  ('auto_backup_enabled', '0'), ('auto_backup_days', '7'),
  ('log_retention_days', '30'), ('commands_synced', '0'),
  ('reply_keyboard_enabled', '0'),
  ('max_reports_before_ban', '5'), ('ban_duration_hours', '24'), ('vip_rate_limit', '100'),
  ('force_join_channels', ''),
  ('vip_media_enabled', '0'), ('vip_bypass_ads', '0'), ('vip_bypass_forcejoin', '0'),
  ('media_photo_enabled', '1'), ('media_video_enabled', '1'), ('media_document_enabled', '1'),
  ('media_audio_enabled', '1'), ('media_voice_enabled', '1'), ('media_animation_enabled', '1'), ('media_sticker_enabled', '1');
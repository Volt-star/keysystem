CREATE TABLE IF NOT EXISTS keys (
  key         TEXT PRIMARY KEY,
  source      TEXT NOT NULL,
  created_by  TEXT,
  created_at  REAL NOT NULL,
  expires_at  REAL,
  hwid        TEXT,
  redeemed_by TEXT,
  redeemed_at TEXT,
  last_reset  REAL,
  device_id   TEXT,
  net_id      TEXT
);
CREATE INDEX IF NOT EXISTS keys_device ON keys(device_id);
CREATE INDEX IF NOT EXISTS keys_net ON keys(net_id);
CREATE INDEX IF NOT EXISTS keys_redeemed ON keys(redeemed_by);

CREATE TABLE IF NOT EXISTS sessions (
  sid         TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL,
  net_id      TEXT NOT NULL,
  stage       TEXT NOT NULL,
  created_at  REAL NOT NULL,
  verified_at REAL
);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id);

CREATE TABLE IF NOT EXISTS used_tokens (
  token   TEXT PRIMARY KEY,
  used_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS rate (
  bucket TEXT NOT NULL,
  ident  TEXT NOT NULL,
  win    INTEGER NOT NULL,
  n      INTEGER NOT NULL,
  exp    INTEGER NOT NULL,
  PRIMARY KEY (bucket, ident, win)
);

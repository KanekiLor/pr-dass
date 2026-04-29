DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS audit_logs;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email VARCHAR(256) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT CHECK(role IN ('ANALYST', 'MANAGER')) DEFAULT 'ANALYST',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  locked INTEGER DEFAULT 0,
  reset_token TEXT DEFAULT NULL,
  reset_token_expires DATETIME DEFAULT NULL,
  bio TEXT DEFAULT NULL
);

CREATE TABLE tickets (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT CHECK(severity in ('LOW','MEDIUM','HIGH')) NOT NULL,
  status TEXT CHECK(status in ('OPEN','IN_PROGRESS','RESOLVED')) DEFAULT 'OPEN',
  owner_id TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE audit_logs(
  id TEXT PRIMARY KEY,
  user_id TEXT,
  action TEXT,
  resource TEXT,
  resource_id TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip_address TEXT,

  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL

);
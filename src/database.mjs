import { DatabaseSync } from 'node:sqlite';

export function openDatabase(path = ':memory:') {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS members (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
    ) STRICT;
    CREATE TABLE IF NOT EXISTS accounts (
      member_id TEXT PRIMARY KEY REFERENCES members(id),
      balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0 AND balance <= 2147483647)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), public_key TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), counter INTEGER NOT NULL DEFAULT 0
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS one_active_device ON devices(member_id) WHERE active = 1;
    CREATE TABLE IF NOT EXISTS cards (
      token TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id),
      active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS one_active_card ON cards(member_id) WHERE active = 1;
    CREATE TABLE IF NOT EXISTS catalog (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, cost INTEGER NOT NULL CHECK(cost > 0),
      stock INTEGER NOT NULL CHECK(stock >= 0)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS contributions (
      id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), title TEXT NOT NULL,
      points INTEGER NOT NULL CHECK(points > 0 AND points <= 100), approved_by TEXT NOT NULL,
      approved_at INTEGER NOT NULL, policy TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES catalog(id),
      member_id TEXT REFERENCES members(id), cost INTEGER NOT NULL CHECK(cost > 0),
      terminal_id TEXT NOT NULL, fulfilled INTEGER NOT NULL DEFAULT 0 CHECK(fulfilled IN (0,1))
    ) STRICT;
    CREATE TABLE IF NOT EXISTS refunds (
      id TEXT PRIMARY KEY, original_entry TEXT NOT NULL UNIQUE,
      member_id TEXT NOT NULL REFERENCES members(id), approved_by TEXT NOT NULL, reason TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY, group_key TEXT NOT NULL, community_id TEXT NOT NULL,
      member_id TEXT NOT NULL REFERENCES members(id), kind TEXT NOT NULL, source_id TEXT NOT NULL,
      version INTEGER NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL,
      nonce TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
      state TEXT NOT NULL DEFAULT 'pending', superseded_by TEXT, created_at INTEGER NOT NULL,
      UNIQUE(group_key, version)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS receipts (
      id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES requests(id),
      member_id TEXT NOT NULL REFERENCES members(id), device_id TEXT NOT NULL REFERENCES devices(id),
      decision TEXT NOT NULL, frame TEXT NOT NULL, signature TEXT NOT NULL, created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS ledger (
      id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), kind TEXT NOT NULL,
      delta INTEGER NOT NULL CHECK(delta != 0), balance_before INTEGER NOT NULL CHECK(balance_before >= 0),
      balance_after INTEGER NOT NULL CHECK(balance_after >= 0), source TEXT NOT NULL UNIQUE,
      original_entry TEXT UNIQUE REFERENCES ledger(id), receipt_id TEXT REFERENCES receipts(id),
      title TEXT NOT NULL, created_at INTEGER NOT NULL,
      CHECK(balance_after = balance_before + delta)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS grants (
      id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id), receipt_id TEXT NOT NULL UNIQUE REFERENCES receipts(id),
      agent_id TEXT NOT NULL, action TEXT NOT NULL, action_digest TEXT NOT NULL, expires_at INTEGER NOT NULL,
      max_uses INTEGER NOT NULL CHECK(max_uses = 1), used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)),
      revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
    ) STRICT;
    CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS executions (
      id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id), action_digest TEXT NOT NULL,
      result TEXT NOT NULL, created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY, actor TEXT NOT NULL, type TEXT NOT NULL, target TEXT NOT NULL,
      details TEXT NOT NULL, created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS receipts_no_update BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT, 'receipts are immutable'); END;
    CREATE TRIGGER IF NOT EXISTS receipts_no_delete BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT, 'receipts are immutable'); END;
  `);
  return db;
}

export function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = fn(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}

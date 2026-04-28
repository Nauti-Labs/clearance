import asyncio
import os
import sqlite3
from datetime import datetime, timezone

try:
    import aiosqlite  # type: ignore
except ImportError:  # pragma: no cover - exercised when optional dependency is missing
    aiosqlite = None


DB_PATH = os.getenv("DB_PATH", "clearance.db")


class _AsyncCursor:
    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    async def fetchone(self):
        return await asyncio.to_thread(self._cursor.fetchone)

    async def fetchall(self):
        return await asyncio.to_thread(self._cursor.fetchall)

    async def close(self):
        await asyncio.to_thread(self._cursor.close)


class _AsyncConnection:
    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection

    @property
    def row_factory(self):
        return self._connection.row_factory

    @row_factory.setter
    def row_factory(self, value):
        self._connection.row_factory = value

    async def execute(self, sql: str, params=()):
        cursor = await asyncio.to_thread(self._connection.execute, sql, params)
        return _AsyncCursor(cursor)

    async def executescript(self, sql: str):
        return await asyncio.to_thread(self._connection.executescript, sql)

    async def commit(self):
        await asyncio.to_thread(self._connection.commit)

    async def close(self):
        await asyncio.to_thread(self._connection.close)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _connect():
    if aiosqlite:
        return await aiosqlite.connect(DB_PATH)
    return _AsyncConnection(sqlite3.connect(DB_PATH, check_same_thread=False))


async def get_db():
    db = await _connect()
    db.row_factory = aiosqlite.Row if aiosqlite else sqlite3.Row
    return db


async def _ensure_column(db, table_name: str, column_name: str, ddl: str):
    cursor = await db.execute(f"PRAGMA table_info({table_name})")
    columns = {row[1] for row in await cursor.fetchall()}
    if column_name not in columns:
        await db.execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")


async def _seed_payees(db):
    cursor = await db.execute("SELECT COUNT(*) FROM approved_payees")
    count = (await cursor.fetchone())[0]
    if count:
        return

    defaults = [
        ("payee_capital_one", "Capital One", "credit_card"),
        ("payee_credit_one", "Credit One Bank", "credit_card"),
        ("payee_netflix", "Netflix", "subscription"),
        ("payee_hulu", "Hulu", "subscription"),
        ("payee_coinbase", "Coinbase", "investment"),
    ]
    now = _utc_now()
    for payee_id, name, category in defaults:
        await db.execute(
            """INSERT INTO approved_payees
               (id, name, category, method, risk_level, created_at, active)
               VALUES (?, ?, ?, ?, ?, ?, 1)""",
            (payee_id, name, category, "manual_review", "verified", now),
        )


async def init_db():
    db = await _connect()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            name TEXT,
            tier TEXT NOT NULL DEFAULT 'starter',
            credits_remaining INTEGER NOT NULL DEFAULT 50,
            credits_reset_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS clearances (
            id TEXT PRIMARY KEY,
            api_key_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            scope TEXT NOT NULL,
            budget_amount REAL,
            budget_currency TEXT DEFAULT 'USD',
            status TEXT NOT NULL DEFAULT 'pending',
            token TEXT,
            approval_url TEXT NOT NULL,
            callback_url TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by TEXT,
            decision_note TEXT,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            clearance_id TEXT,
            api_key_id TEXT,
            event TEXT NOT NULL,
            actor TEXT,
            ip TEXT,
            user_agent TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS webhooks (
            id TEXT PRIMARY KEY,
            api_key_id TEXT NOT NULL,
            url TEXT NOT NULL,
            secret TEXT NOT NULL,
            events TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
        );

        CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            api_key_id TEXT,
            email TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            crypto_currency TEXT,
            tx_hash TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            tier TEXT NOT NULL,
            provider TEXT NOT NULL,
            provider_ref TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS family_sources (
            id TEXT PRIMARY KEY,
            source_key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'setup_needed',
            last_synced_at TEXT,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS family_accounts (
            id TEXT PRIMARY KEY,
            source_key TEXT NOT NULL,
            external_id TEXT,
            institution TEXT NOT NULL,
            name TEXT NOT NULL,
            account_type TEXT NOT NULL,
            subtype TEXT,
            last4 TEXT,
            balance REAL NOT NULL DEFAULT 0,
            available REAL,
            currency TEXT NOT NULL DEFAULT 'USD',
            status TEXT NOT NULL DEFAULT 'active',
            is_live INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            metadata TEXT,
            UNIQUE(source_key, external_id)
        );

        CREATE TABLE IF NOT EXISTS family_bills (
            id TEXT PRIMARY KEY,
            source_key TEXT NOT NULL,
            external_id TEXT,
            payee TEXT NOT NULL,
            category TEXT,
            amount REAL NOT NULL,
            minimum_due REAL,
            due_date TEXT NOT NULL,
            autopay_enabled INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            debtor_account TEXT,
            notes TEXT,
            updated_at TEXT NOT NULL,
            metadata TEXT,
            UNIQUE(source_key, external_id)
        );

        CREATE TABLE IF NOT EXISTS family_debts (
            id TEXT PRIMARY KEY,
            source_key TEXT NOT NULL,
            external_id TEXT,
            creditor TEXT NOT NULL,
            balance REAL NOT NULL,
            apr REAL,
            minimum_payment REAL NOT NULL DEFAULT 0,
            due_date TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            updated_at TEXT NOT NULL,
            metadata TEXT,
            UNIQUE(source_key, external_id)
        );

        CREATE TABLE IF NOT EXISTS family_subscriptions (
            id TEXT PRIMARY KEY,
            source_key TEXT NOT NULL,
            external_id TEXT,
            merchant TEXT NOT NULL,
            amount REAL NOT NULL,
            billing_cycle TEXT NOT NULL DEFAULT 'monthly',
            next_charge_date TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            recommendation TEXT,
            updated_at TEXT NOT NULL,
            metadata TEXT,
            UNIQUE(source_key, external_id)
        );

        CREATE TABLE IF NOT EXISTS family_goals (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            target_amount REAL NOT NULL,
            current_amount REAL NOT NULL DEFAULT 0,
            target_date TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            updated_at TEXT NOT NULL,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS family_credit_scores (
            id TEXT PRIMARY KEY,
            person_name TEXT NOT NULL,
            bureau TEXT NOT NULL,
            score INTEGER NOT NULL,
            source_key TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS family_alerts (
            id TEXT PRIMARY KEY,
            source_key TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            detail TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            updated_at TEXT NOT NULL,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS approved_payees (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            category TEXT,
            method TEXT NOT NULL DEFAULT 'manual_review',
            risk_level TEXT NOT NULL DEFAULT 'verified',
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS family_actions (
            id TEXT PRIMARY KEY,
            action_type TEXT NOT NULL,
            title TEXT NOT NULL,
            payee TEXT,
            amount REAL,
            currency TEXT NOT NULL DEFAULT 'USD',
            source_account TEXT,
            destination_hint TEXT,
            status TEXT NOT NULL DEFAULT 'pending_human_approval',
            requested_by TEXT,
            approved_by TEXT,
            human_note TEXT,
            recommended_execution_date TEXT,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS family_sync_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_key TEXT NOT NULL,
            actor TEXT,
            snapshot_kind TEXT NOT NULL,
            counts TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_clearances_api_key ON clearances(api_key_id);
        CREATE INDEX IF NOT EXISTS idx_clearances_status ON clearances(status);
        CREATE INDEX IF NOT EXISTS idx_audit_clearance ON audit_log(clearance_id);
        CREATE INDEX IF NOT EXISTS idx_payments_email ON payments(email);
        CREATE INDEX IF NOT EXISTS idx_family_accounts_source ON family_accounts(source_key);
        CREATE INDEX IF NOT EXISTS idx_family_bills_due_date ON family_bills(due_date);
        CREATE INDEX IF NOT EXISTS idx_family_debts_creditor ON family_debts(creditor);
        CREATE INDEX IF NOT EXISTS idx_family_actions_status ON family_actions(status);
        CREATE INDEX IF NOT EXISTS idx_family_alerts_status ON family_alerts(status);
    """)

    await _ensure_column(db, "payments", "metadata", "metadata TEXT")
    await _seed_payees(db)

    await db.commit()
    await db.close()

#!/usr/bin/env python3
"""
Database Initialization Script
Run this to initialize all database tables including the ai_providers table
"""

import logging
import sqlite3

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

DB_PATH = "stock_news.db"


def init_all_tables():
    """Initialize all database tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    logger.info("Initializing database tables...")

    # Create news table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticker TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            url TEXT UNIQUE,
            source TEXT,
            published_date TEXT,
            sentiment_score REAL,
            sentiment_label TEXT,
            engagement_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    logger.info("✓ News table initialized")

    # Create alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticker TEXT NOT NULL,
            news_id INTEGER,
            alert_type TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (news_id) REFERENCES news (id)
        )
    """)
    logger.info("✓ Alerts table initialized")

    # Create monitor_status table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitor_status (
            id INTEGER PRIMARY KEY,
            last_check TIMESTAMP,
            status TEXT,
            message TEXT
        )
    """)
    logger.info("✓ Monitor status table initialized")

    # Create stocks table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stocks (
            ticker TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            market TEXT DEFAULT 'US',
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    logger.info("✓ Stocks table initialized")

    # Create settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    logger.info("✓ Settings table initialized")

    # Create AI providers table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_name TEXT NOT NULL,
            api_key TEXT NOT NULL,
            model TEXT,
            is_active INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    logger.info("✓ AI providers table initialized")

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    """)
    logger.info("✓ Users table initialized")

    # Create sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    logger.info("✓ Sessions table initialized")

    # Create indexes for better performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ticker ON news(ticker)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON news(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sentiment ON news(sentiment_label)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_url ON news(url)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON users(email)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_session_token ON sessions(session_token)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_session_expires ON sessions(expires_at)"
    )
    logger.info("✓ Database indexes created")

    conn.commit()
    conn.close()

    logger.info("\n✅ All database tables initialized successfully!")
    logger.info(f"Database location: {DB_PATH}")


if __name__ == "__main__":
    init_all_tables()

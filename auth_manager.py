#!/usr/bin/env python3
"""
Authentication Manager
Handles user registration, login, and session management
"""

import hashlib
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = "stock_news.db"


def init_auth_tables():
    """Initialize authentication tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

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

    # Create indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON users(email)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_session_token ON sessions(session_token)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_session_expires ON sessions(expires_at)"
    )

    conn.commit()
    conn.close()
    logger.info("Authentication tables initialized successfully")


def hash_password(password, salt=None):
    """Hash password with salt using SHA-256"""
    if salt is None:
        salt = secrets.token_hex(32)

    # Use PBKDF2 for key derivation (more secure than simple SHA-256)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    )

    return f"{salt}${password_hash.hex()}"


def verify_password(password, password_hash):
    """Verify password against hash"""
    try:
        salt, hash_hex = password_hash.split("$")
        new_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
        )
        return new_hash.hex() == hash_hex
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def create_user(username, email, password):
    """Create a new user account"""
    try:
        # Validate input
        if len(username) < 3:
            return {"success": False, "error": "Username must be at least 3 characters"}

        if len(password) < 8:
            return {"success": False, "error": "Password must be at least 8 characters"}

        if "@" not in email:
            return {"success": False, "error": "Invalid email address"}

        # Hash password
        password_hash = hash_password(password)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
        )
        if cursor.fetchone():
            conn.close()
            return {"success": False, "error": "Username or email already exists"}

        # Insert new user
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        """,
            (username, email, password_hash),
        )

        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"User created successfully: {username} (ID: {user_id})")
        return {"success": True, "user_id": user_id, "username": username}

    except sqlite3.IntegrityError as e:
        logger.error(f"Database integrity error: {e}")
        return {"success": False, "error": "Username or email already exists"}
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return {"success": False, "error": "An error occurred during registration"}


def authenticate_user(username, password):
    """Authenticate user with username/email and password"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Find user by username or email
        cursor.execute(
            """
            SELECT id, username, email, password_hash, is_active
            FROM users
            WHERE (username = ? OR email = ?) AND is_active = 1
        """,
            (username, username),
        )

        user = cursor.fetchone()

        if not user:
            conn.close()
            return {"success": False, "error": "Invalid username or password"}

        # Verify password
        if not verify_password(password, user["password_hash"]):
            conn.close()
            return {"success": False, "error": "Invalid username or password"}

        # Update last login
        cursor.execute(
            """
            UPDATE users
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        """,
            (user["id"],),
        )

        conn.commit()
        conn.close()

        logger.info(f"User authenticated successfully: {user['username']}")
        return {
            "success": True,
            "user_id": user["id"],
            "username": user["username"],
            "email": user["email"],
        }

    except Exception as e:
        logger.error(f"Error authenticating user: {e}")
        return {"success": False, "error": "An error occurred during login"}


def create_session(user_id, ip_address=None, user_agent=None, expires_in_days=30):
    """Create a new session for user"""
    try:
        session_token = secrets.token_urlsafe(64)
        expires_at = datetime.now() + timedelta(days=expires_in_days)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO sessions (user_id, session_token, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        """,
            (user_id, session_token, expires_at, ip_address, user_agent),
        )

        conn.commit()
        conn.close()

        logger.info(f"Session created for user_id: {user_id}")
        return {
            "success": True,
            "session_token": session_token,
            "expires_at": expires_at,
        }

    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return {"success": False, "error": "Failed to create session"}


def validate_session(session_token):
    """Validate session token and return user info"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT s.*, u.username, u.email, u.is_active
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.expires_at > CURRENT_TIMESTAMP AND u.is_active = 1
        """,
            (session_token,),
        )

        session = cursor.fetchone()
        conn.close()

        if not session:
            return {"success": False, "error": "Invalid or expired session"}

        return {
            "success": True,
            "user_id": session["user_id"],
            "username": session["username"],
            "email": session["email"],
        }

    except Exception as e:
        logger.error(f"Error validating session: {e}")
        return {"success": False, "error": "Session validation failed"}


def delete_session(session_token):
    """Delete a session (logout)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))

        conn.commit()
        conn.close()

        logger.info("Session deleted successfully")
        return {"success": True}

    except Exception as e:
        logger.error(f"Error deleting session: {e}")
        return {"success": False, "error": "Failed to logout"}


def cleanup_expired_sessions():
    """Remove expired sessions from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
        deleted_count = cursor.rowcount

        conn.commit()
        conn.close()

        logger.info(f"Cleaned up {deleted_count} expired sessions")
        return {"success": True, "deleted_count": deleted_count}

    except Exception as e:
        logger.error(f"Error cleaning up sessions: {e}")
        return {"success": False, "error": "Failed to cleanup sessions"}


def get_user_by_id(user_id):
    """Get user information by user ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, email, created_at, last_login, is_active
            FROM users
            WHERE id = ?
        """,
            (user_id,),
        )

        user = cursor.fetchone()
        conn.close()

        if not user:
            return {"success": False, "error": "User not found"}

        return {
            "success": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "created_at": user["created_at"],
                "last_login": user["last_login"],
                "is_active": user["is_active"],
            },
        }

    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return {"success": False, "error": "Failed to retrieve user"}


def change_password(user_id, old_password, new_password):
    """Change user password"""
    try:
        if len(new_password) < 8:
            return {"success": False, "error": "Password must be at least 8 characters"}

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get current password hash
        cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return {"success": False, "error": "User not found"}

        # Verify old password
        if not verify_password(old_password, user["password_hash"]):
            conn.close()
            return {"success": False, "error": "Incorrect current password"}

        # Hash new password
        new_password_hash = hash_password(new_password)

        # Update password
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_password_hash, user_id),
        )

        # Invalidate all existing sessions for security
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

        conn.commit()
        conn.close()

        logger.info(f"Password changed successfully for user_id: {user_id}")
        return {"success": True}

    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return {"success": False, "error": "Failed to change password"}


if __name__ == "__main__":
    # Initialize tables
    init_auth_tables()
    print("✅ Authentication tables initialized successfully!")

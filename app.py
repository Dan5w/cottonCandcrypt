import os
import io
import json
import secrets
import subprocess
import threading
import time
import hashlib
import base64
import gzip
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_file, session, redirect, url_for
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import pymysql
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dbvault-secret-key-2024-change-in-production")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def generate_user_key() -> str:
    return secrets.token_hex(24)  # 48-char hex string, unique per user


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "redirect": "/login"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Only role 0 (admin) can access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        if session.get("user_role", 1) != 0:
            return jsonify({"error": "Forbidden", "message": "Se requieren permisos de administrador"}), 403
        return f(*args, **kwargs)
    return decorated


def backup_role_required(f):
    """Allow role 0 (admin) and role 2 (backup+restore)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        if session.get("user_role", 1) not in (0, 2):
            return jsonify({"error": "Forbidden", "message": "Acción no permitida para tu rol"}), 403
        return f(*args, **kwargs)
    return decorated


def verify_user_key(user_key: str) -> bool:
    """Check that the provided key matches the session user's stored key."""
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT user_key FROM users WHERE username=%s AND active=1", (session.get("user"),))
        row = c.fetchone()
    db.close()
    return row is not None and decrypt_db_key(row["user_key"]) == user_key

BASE_DIR = Path(__file__).parent
BACKUP_DIR = BASE_DIR / "backups"
LOG_DIR = BASE_DIR / "logs"

BACKUP_DIR.mkdir(exist_ok=True)

# ─── Vault key (encrypts user_key values stored in DB) ────────────────────────
_vault_fernet = None

def get_vault_fernet() -> Fernet:
    global _vault_fernet
    if _vault_fernet is not None:
        return _vault_fernet
    key_path = BASE_DIR / "vault.key"
    if key_path.exists():
        key = key_path.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        key_path.write_bytes(key)
    _vault_fernet = Fernet(key)
    return _vault_fernet

def encrypt_db_key(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    return get_vault_fernet().encrypt(plaintext.encode()).decode()

def decrypt_db_key(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    try:
        return get_vault_fernet().decrypt(ciphertext.encode()).decode()
    except Exception:
        return ciphertext  # plain-text (pre-migration), return as-is
LOG_DIR.mkdir(exist_ok=True)

# ─── MySQL Catalog Config ─────────────────────────────────────────────────────

MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASS = os.environ.get("MYSQL_PASS", "")
MYSQL_DB   = os.environ.get("MYSQL_DB", "backups0")

MYSQLDUMP_PATH = os.environ.get("MYSQLDUMP_PATH", r"C:\Program Files\MySQL\MySQL Server 9.2\bin\mysqldump.exe")
MYSQL_PATH     = os.environ.get("MYSQL_PATH", r"C:\Program Files\MySQL\MySQL Server 9.2\bin\mysql.exe")

def get_catalog_conn():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASS,
        database=MYSQL_DB,
        autocommit=False,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )

# ─── Encryption ───────────────────────────────────────────────────────────────

def generate_key(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(data: bytes, password: str, cipher_method: str = "fernet") -> bytes:
    if cipher_method == "aes-256-gcm":
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        raw_key = kdf.derive(password.encode())
        nonce = os.urandom(12)
        ciphertext = AESGCM(raw_key).encrypt(nonce, data, None)
        return salt + nonce + ciphertext
    elif cipher_method == "chacha20":
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        raw_key = kdf.derive(password.encode())
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(raw_key).encrypt(nonce, data, None)
        return salt + nonce + ciphertext
    else:
        key, salt = generate_key(password)
        f = Fernet(key)
        encrypted = f.encrypt(data)
        return salt + encrypted

def decrypt_file(data: bytes, password: str, cipher_method: str = "fernet") -> bytes:
    if cipher_method == "aes-256-gcm":
        salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        raw_key = kdf.derive(password.encode())
        return AESGCM(raw_key).decrypt(nonce, ciphertext, None)
    elif cipher_method == "chacha20":
        salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        raw_key = kdf.derive(password.encode())
        return ChaCha20Poly1305(raw_key).decrypt(nonce, ciphertext, None)
    else:
        salt = data[:16]
        encrypted = data[16:]
        key, _ = generate_key(password, salt)
        f = Fernet(key)
        return f.decrypt(encrypted)

# ─── Catalog Schema Init ──────────────────────────────────────────────────────

def init_catalog():
    # First create the schema if it doesn't exist (connect without DB)
    root_conn = pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASS,
        charset="utf8mb4",
    )
    with root_conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    root_conn.commit()
    root_conn.close()

    conn = get_catalog_conn()
    with conn.cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                db_type VARCHAR(50) NOT NULL,
                host VARCHAR(255),
                port INT,
                db_name VARCHAR(255),
                username VARCHAR(255),
                password VARCHAR(255),
                created_at DATETIME DEFAULT NOW()
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS backups (
                id INT AUTO_INCREMENT PRIMARY KEY,
                connection_id INT,
                db_name VARCHAR(255),
                filename VARCHAR(512) NOT NULL,
                filepath VARCHAR(1024) NOT NULL,
                size_bytes BIGINT,
                compressed TINYINT DEFAULT 0,
                encrypted TINYINT DEFAULT 0,
                checksum VARCHAR(128),
                status VARCHAR(50) DEFAULT 'completed',
                error_msg TEXT,
                backup_type VARCHAR(50) DEFAULT 'manual',
                created_at DATETIME DEFAULT NOW(),
                FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE SET NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INT AUTO_INCREMENT PRIMARY KEY,
                connection_id INT,
                frequency VARCHAR(50),
                run_time VARCHAR(5) DEFAULT '00:00',
                encrypt TINYINT DEFAULT 1,
                compress TINYINT DEFAULT 1,
                retain_days INT DEFAULT 30,
                active TINYINT DEFAULT 1,
                last_run DATETIME,
                next_run DATETIME,
                created_at DATETIME DEFAULT NOW(),
                FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE
            )
        """)
        try:
            c.execute("ALTER TABLE schedules ADD COLUMN run_time VARCHAR(5) DEFAULT '00:00'")
            conn.commit()
        except Exception:
            pass
        c.execute("""
            CREATE TABLE IF NOT EXISTS restores (
                id INT AUTO_INCREMENT PRIMARY KEY,
                backup_id INT,
                target_conn_id INT,
                target_conn_name VARCHAR(255),
                db_name VARCHAR(255),
                status VARCHAR(50) DEFAULT 'completed',
                error_msg TEXT,
                user_id INT,
                created_at DATETIME DEFAULT NOW(),
                FOREIGN KEY(backup_id) REFERENCES backups(id) ON DELETE SET NULL,
                FOREIGN KEY(target_conn_id) REFERENCES connections(id) ON DELETE SET NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                level VARCHAR(20),
                message TEXT,
                user_id INT,
                ip_address VARCHAR(45),
                created_at DATETIME DEFAULT NOW(),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        for migration_sql in [
            "ALTER TABLE logs ADD COLUMN user_id INT",
            "ALTER TABLE logs DROP COLUMN username",
            "ALTER TABLE logs ADD CONSTRAINT fk_logs_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL",
            "ALTER TABLE logs ADD COLUMN ip_address VARCHAR(45)",
        ]:
            try:
                c.execute(migration_sql)
            except Exception:
                pass
        c.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id   TINYINT PRIMARY KEY,
                name VARCHAR(50)  NOT NULL,
                description VARCHAR(255)
            )
        """)
        for role_row in [
            (0, "Administrador", "Acceso total + gestión de usuarios"),
            (1, "Lector",        "Solo lectura — sin acciones"),
            (2, "Técnico",       "Backups y restauraciones"),
        ]:
            c.execute("""
                INSERT INTO roles (id, name, description) VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE name=VALUES(name), description=VALUES(description)
            """, role_row)

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(64) NOT NULL,
                user_key VARCHAR(256) NOT NULL DEFAULT '',
                role TINYINT NOT NULL DEFAULT 0,
                active TINYINT DEFAULT 1,
                created_at DATETIME DEFAULT NOW(),
                FOREIGN KEY(role) REFERENCES roles(id)
            )
        """)
        # Migration: add/modify columns on existing tables
        for migration_sql in [
            "ALTER TABLE users ADD COLUMN user_key VARCHAR(256) NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD COLUMN role TINYINT NOT NULL DEFAULT 0",
            "ALTER TABLE users MODIFY COLUMN user_key VARCHAR(256) NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD CONSTRAINT fk_users_role FOREIGN KEY(role) REFERENCES roles(id)",
            "ALTER TABLE backups DROP COLUMN connection_name",
            "ALTER TABLE backups ADD COLUMN cipher_method VARCHAR(30) DEFAULT 'fernet'",
            "ALTER TABLE backups ADD COLUMN custom_key_used TINYINT DEFAULT 0",
            "ALTER TABLE schedules ADD CONSTRAINT fk_schedules_conn FOREIGN KEY(connection_id) REFERENCES connections(id) ON DELETE CASCADE",
        ]:
            try:
                c.execute(migration_sql)
            except Exception:
                pass

        # Ensure root user exists without touching AUTO_INCREMENT on every restart
        c.execute("SELECT id, role, user_key FROM users WHERE username='root'")
        root_row = c.fetchone()
        if not root_row:
            root_key = encrypt_db_key(generate_user_key())
            c.execute(
                "INSERT INTO users (username, password_hash, user_key, role) VALUES ('root', %s, %s, 0)",
                (hash_password("password"), root_key)
            )
        else:
            # Fix missing role or empty key without burning an AUTO_INCREMENT value
            updates = {}
            if root_row["role"] is None:
                updates["role"] = 0
            if not root_row["user_key"]:
                updates["user_key"] = encrypt_db_key(generate_user_key())
            if updates:
                set_clause = ", ".join(f"{k}=%s" for k in updates)
                c.execute(f"UPDATE users SET {set_clause} WHERE username='root'", list(updates.values()))
    conn.commit()

    # Migrate plain-text user_keys to encrypted form
    with conn.cursor() as c:
        c.execute("SELECT id, user_key FROM users WHERE user_key != ''")
        rows = c.fetchall()
    for row in rows:
        raw = row["user_key"]
        try:
            get_vault_fernet().decrypt(raw.encode())  # already encrypted — skip
        except Exception:
            with conn.cursor() as c:
                c.execute("UPDATE users SET user_key=%s WHERE id=%s", (encrypt_db_key(raw), row["id"]))
    conn.commit()
    conn.close()

def get_role_names() -> dict:
    """Return {id: name} dict loaded from the roles table."""
    try:
        db = get_catalog_conn()
        with db.cursor() as c:
            c.execute("SELECT id, name FROM roles ORDER BY id")
            rows = c.fetchall()
        db.close()
        return {r["id"]: r["name"] for r in rows}
    except Exception:
        return {0: "Administrador", 1: "Lector", 2: "Técnico"}


def get_roles_full() -> list:
    """Return full roles list [{id, name, description}] for the API."""
    try:
        db = get_catalog_conn()
        with db.cursor() as c:
            c.execute("SELECT id, name, description FROM roles ORDER BY id")
            rows = c.fetchall()
        db.close()
        return [{"id": r["id"], "name": r["name"], "description": r["description"]} for r in rows]
    except Exception:
        return []


def log_event(level: str, message: str, user_id=None):
    try:
        uid = user_id
        ip_address = None
        try:
            if uid is None:
                uid = session.get("user_id")
            ip_address = request.remote_addr
        except RuntimeError:
            pass  # No active request context (background thread)
        conn = get_catalog_conn()
        with conn.cursor() as c:
            c.execute(
                "INSERT INTO logs (level, message, user_id, ip_address) VALUES (%s, %s, %s, %s)",
                (level, message, uid, ip_address)
            )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Log error: {e}")

# ─── DB Connection Testing ────────────────────────────────────────────────────

def test_connection(db_type, host, port, database, username, password):
    try:
        if db_type == "mysql":
            conn = pymysql.connect(host=host, port=int(port), user=username,
                                   password=password, database=database, connect_timeout=5)
            conn.close()
        elif db_type == "postgresql":
            import psycopg2
            conn = psycopg2.connect(host=host, port=int(port), dbname=database,
                                    user=username, password=password, connect_timeout=5)
            conn.close()
        elif db_type == "sqlite":
            import sqlite3
            conn = sqlite3.connect(database)
            conn.close()
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)

# ─── Backup Engine ────────────────────────────────────────────────────────────

def do_backup(conn_id, encrypt=True, compress=True, password="dbvault2024", backup_type="manual", cipher_method="fernet", custom_key_used=False):
    conn = get_catalog_conn()
    with conn.cursor() as c:
        c.execute("SELECT * FROM connections WHERE id=%s", (conn_id,))
        row = c.fetchone()
    conn.close()

    if not row:
        return False, "Connection not found"

    name      = row["name"]
    db_type   = row["db_type"]
    host      = row["host"]
    port      = row["port"]
    database  = row["db_name"]
    username  = row["username"]
    db_pass   = row["password"]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_")
    ext = ".sql.gz.enc" if compress and encrypt else ".sql.gz" if compress else ".sql.enc" if encrypt else ".sql"
    filename = f"{safe_name}_{timestamp}{ext}"
    filepath = BACKUP_DIR / filename

    try:
        if db_type == "mysql":
            cmd = [MYSQLDUMP_PATH, "-h", host, "-P", str(port), "-u", username,
                   f"-p{db_pass}", database]
            result = subprocess.run(cmd, capture_output=True, timeout=300)
            if result.returncode != 0:
                raise Exception(result.stderr.decode())
            sql_data = result.stdout

        elif db_type == "postgresql":
            env = os.environ.copy()
            env["PGPASSWORD"] = db_pass
            cmd = ["pg_dump", "-h", host, "-p", str(port), "-U", username, database]
            result = subprocess.run(cmd, capture_output=True, env=env, timeout=300)
            if result.returncode != 0:
                raise Exception(result.stderr.decode())
            sql_data = result.stdout

        elif db_type == "sqlite":
            import sqlite3
            src_conn = sqlite3.connect(database)
            sql_data = "\n".join(src_conn.iterdump()).encode("utf-8")
            src_conn.close()
        else:
            raise Exception(f"Unsupported DB type: {db_type}")

        if compress:
            sql_data = gzip.compress(sql_data)
        if encrypt:
            sql_data = encrypt_file(sql_data, password, cipher_method)

        with open(filepath, "wb") as f:
            f.write(sql_data)

        size = os.path.getsize(filepath)
        checksum = hashlib.sha256(sql_data).hexdigest()

        db = get_catalog_conn()
        with db.cursor() as c:
            c.execute("""
                INSERT INTO backups (connection_id, db_name, filename, filepath,
                    size_bytes, compressed, encrypted, checksum, status, backup_type,
                    cipher_method, custom_key_used)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (conn_id, database, filename, str(filepath),
                  size, int(compress), int(encrypt), checksum, "completed", backup_type,
                  cipher_method if encrypt else None, int(custom_key_used)))
        db.commit()
        db.close()

        log_event("INFO", f"Backup completed: {filename} ({size} bytes)")
        return True, {"filename": filename, "size": size, "checksum": checksum}

    except Exception as e:
        error = str(e)
        db = get_catalog_conn()
        with db.cursor() as c:
            c.execute("""
                INSERT INTO backups (connection_id, db_name, filename, filepath,
                    size_bytes, status, error_msg, backup_type)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (conn_id, database or "", filename, str(filepath), 0, "failed", error, backup_type))
        db.commit()
        db.close()
        log_event("ERROR", f"Backup failed for {name}: {error}")
        return False, error

# ─── Restore Engine ───────────────────────────────────────────────────────────

def do_restore(backup_id, target_conn_id, password="dbvault2024"):
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT * FROM backups WHERE id=%s", (backup_id,))
        bk = c.fetchone()
        c.execute("SELECT * FROM connections WHERE id=%s", (target_conn_id,))
        conn_row = c.fetchone()
    db.close()

    if not bk or not conn_row:
        return False, "Backup or connection not found"

    filepath  = Path(bk["filepath"])
    encrypted = bk["encrypted"]
    compressed = bk["compressed"]
    cipher    = bk.get("cipher_method") or "fernet"
    name      = conn_row["name"]
    db_type   = conn_row["db_type"]
    host      = conn_row["host"]
    port      = conn_row["port"]
    database  = conn_row["db_name"]
    username  = conn_row["username"]
    db_pass   = conn_row["password"]

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        if encrypted:
            data = decrypt_file(data, password, cipher)
        if compressed:
            data = gzip.decompress(data)

        sql_text = data.decode("utf-8")

        if db_type == "mysql":
            conn = pymysql.connect(host=host, port=int(port), user=username,
                                   password=db_pass, database=database)
            with conn.cursor() as cursor:
                for statement in sql_text.split(";"):
                    s = statement.strip()
                    if s:
                        cursor.execute(s)
            conn.commit()
            conn.close()

        elif db_type == "postgresql":
            import psycopg2
            conn = psycopg2.connect(host=host, port=int(port), dbname=database,
                                    user=username, password=db_pass)
            cursor = conn.cursor()
            cursor.execute(sql_text)
            conn.commit()
            conn.close()

        elif db_type == "sqlite":
            import sqlite3
            conn = sqlite3.connect(database)
            conn.executescript(sql_text)
            conn.close()

        log_event("INFO", f"Restore completed: backup {backup_id} → {name}")
        _record_restore(backup_id, target_conn_id, name, database, "completed")
        return True, "Restore completed successfully"

    except Exception as e:
        log_event("ERROR", f"Restore failed: {str(e)}")
        _record_restore(backup_id, target_conn_id, name, database, "failed", str(e))
        return False, str(e)

def _record_restore(backup_id, target_conn_id, conn_name, db_name, status, error_msg=None):
    try:
        uid = None
        try:
            uid = session.get("user_id")
        except RuntimeError:
            pass
        db = get_catalog_conn()
        with db.cursor() as c:
            c.execute(
                "INSERT INTO restores (backup_id, target_conn_id, target_conn_name, db_name, status, error_msg, user_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (backup_id, target_conn_id, conn_name, db_name, status, error_msg, uid)
            )
        db.commit()
        db.close()
    except Exception as e:
        print(f"Record restore error: {e}")

# ─── Scheduler ────────────────────────────────────────────────────────────────

scheduler_thread = None
scheduler_running = False

def run_scheduled_backups():
    while scheduler_running:
        now = datetime.now()
        try:
            db = get_catalog_conn()
            with db.cursor() as c:
                c.execute("SELECT * FROM schedules WHERE active=1")
                schedules = c.fetchall()
            db.close()
            # Fetch admin key once for encrypted scheduled backups
            admin_key = "dbvault2024"
            try:
                db2 = get_catalog_conn()
                with db2.cursor() as c2:
                    c2.execute("SELECT user_key FROM users WHERE role=0 AND active=1 LIMIT 1")
                    admin_row = c2.fetchone()
                db2.close()
                if admin_row and admin_row["user_key"]:
                    admin_key = decrypt_db_key(admin_row["user_key"])
            except Exception:
                pass

            for s in schedules:
                next_run = s["next_run"]
                if next_run and next_run <= now:
                    do_backup(s["connection_id"], bool(s["encrypt"]), bool(s["compress"]), admin_key, backup_type="scheduled")
                    freq     = s["frequency"]
                    run_time = s.get("run_time") or "00:00"
                    db = get_catalog_conn()
                    with db.cursor() as c:
                        if freq == "once":
                            c.execute("UPDATE schedules SET last_run=%s, active=0 WHERE id=%s", (now, s["id"]))
                        else:
                            nxt = calc_next_run(freq, run_time)
                            c.execute("UPDATE schedules SET last_run=%s, next_run=%s WHERE id=%s",
                                      (now, nxt, s["id"]))
                    db.commit()
                    db.close()

                    # Enforce retention: delete old backups beyond retain_days for this schedule
                    retain = s.get("retain_days") or 30
                    cutoff = now - timedelta(days=retain)
                    db = get_catalog_conn()
                    with db.cursor() as c:
                        c.execute("""
                            SELECT id, filepath FROM backups
                            WHERE connection_id=%s AND backup_type='scheduled'
                            AND status='completed' AND created_at < %s
                        """, (s["connection_id"], cutoff))
                        old_backups = c.fetchall()
                    db.close()
                    for bk in old_backups:
                        try:
                            if bk["filepath"] and os.path.exists(bk["filepath"]):
                                os.remove(bk["filepath"])
                        except Exception:
                            pass
                        db = get_catalog_conn()
                        with db.cursor() as c:
                            c.execute("DELETE FROM backups WHERE id=%s", (bk["id"],))
                        db.commit()
                        db.close()
        except Exception as e:
            print(f"Scheduler error: {e}")
        time.sleep(60)

def start_scheduler():
    global scheduler_thread, scheduler_running
    scheduler_running = True
    scheduler_thread = threading.Thread(target=run_scheduled_backups, daemon=True)
    scheduler_thread.start()


# ─── Encrypted Log Writer ────────────────────────────────────────────────────

LOG_ENCRYPT_INTERVAL = 300  # seconds between encrypted log snapshots

def _get_log_encrypt_key():
    try:
        db = get_catalog_conn()
        with db.cursor() as c:
            c.execute("SELECT user_key FROM users WHERE role=0 AND active=1 LIMIT 1")
            row = c.fetchone()
        db.close()
        if row and row["user_key"]:
            return decrypt_db_key(row["user_key"])
    except Exception:
        pass
    return "dbvault-log-key-default"


def run_log_writer():
    while scheduler_running:
        try:
            db = get_catalog_conn()
            with db.cursor() as c:
                c.execute("""
                    SELECT l.id, l.level, l.message, l.created_at, l.ip_address, u.username
                    FROM logs l LEFT JOIN users u ON l.user_id = u.id
                    ORDER BY l.created_at DESC LIMIT 500
                """)
                rows = c.fetchall()
            db.close()
            if rows:
                import json as _json
                plain = _json.dumps([{
                    "id": r["id"], "level": r["level"], "message": r["message"],
                    "created_at": str(r["created_at"]),
                    "username": r.get("username"), "ip_address": r.get("ip_address")
                } for r in rows], ensure_ascii=False, indent=2).encode("utf-8")
                key = _get_log_encrypt_key()
                encrypted = encrypt_file(plain, key)
                log_file = LOG_DIR / "activity_log.enc"
                log_file.write_bytes(encrypted)
        except Exception as e:
            print(f"Log writer error: {e}")
        time.sleep(LOG_ENCRYPT_INTERVAL)


def start_log_writer():
    t = threading.Thread(target=run_log_writer, daemon=True)
    t.start()


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/login")
def login_page():
    if "user" in session:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.json or {}
    username = d.get("username", "").strip()
    password = d.get("password", "")
    if not username or not password:
        return jsonify({"success": False, "error": "Usuario y contraseña requeridos"}), 400
    password_hash = hash_password(password)
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute(
            "SELECT id, username, role, user_key FROM users WHERE username=%s AND password_hash=%s AND active=1",
            (username, password_hash)
        )
        user = c.fetchone()
    db.close()
    if not user:
        log_event("WARN", f"Failed login attempt for user: {username}")
        return jsonify({"success": False, "error": "Credenciales inválidas"}), 401
    session["user"]      = user["username"]
    session["user_id"]   = user["id"]
    session["user_role"] = user["role"]
    log_event("INFO", f"User '{username}' logged in")
    role_names = get_role_names()
    return jsonify({
        "success":  True,
        "username": user["username"],
        "role":     user["role"],
        "role_name": role_names.get(user["role"], "Desconocido"),
        "user_key": decrypt_db_key(user["user_key"]),
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    user = session.pop("user", None)
    session.pop("user_id", None)
    session.pop("user_role", None)
    if user:
        log_event("INFO", f"User '{user}' logged out")
    return jsonify({"success": True})


@app.route("/api/me")
@login_required
def get_me():
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT id, username, role, user_key FROM users WHERE id=%s", (session["user_id"],))
        user = c.fetchone()
    db.close()
    role_names = get_role_names()
    return jsonify({
        "id":       user["id"],
        "username": user["username"],
        "role":     user["role"],
        "role_name": role_names.get(user["role"], "Desconocido"),
        "user_key": decrypt_db_key(user["user_key"]),
    })


# ─── User Management (admin only) ────────────────────────────────────────────

@app.route("/api/roles", methods=["GET"])
@login_required
def api_get_roles():
    return jsonify(get_roles_full())


@app.route("/api/users", methods=["GET"])
@admin_required
def get_users():
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT id, username, role, user_key, active, created_at FROM users ORDER BY id")
        rows = c.fetchall()
    db.close()
    role_names = get_role_names()
    return jsonify([{
        "id": r["id"], "username": r["username"],
        "role": r["role"], "role_name": role_names.get(r["role"], "?"),
        "user_key": decrypt_db_key(r["user_key"]), "active": r["active"],
        "created_at": str(r["created_at"])
    } for r in rows])


@app.route("/api/users", methods=["POST"])
@admin_required
def create_user():
    d = request.json or {}
    username = d.get("username", "").strip()
    password = d.get("password", "")
    role     = int(d.get("role", 1))
    if not username or not password:
        return jsonify({"success": False, "error": "Usuario y contraseña requeridos"}), 400
    if role not in (1, 2):
        return jsonify({"success": False, "error": "Rol inválido (1 o 2)"}), 400
    pw_hash  = hash_password(password)
    user_key = generate_user_key()
    db = get_catalog_conn()
    try:
        with db.cursor() as c:
            c.execute(
                "INSERT INTO users (username, password_hash, user_key, role) VALUES (%s,%s,%s,%s)",
                (username, pw_hash, encrypt_db_key(user_key), role)
            )
            uid = c.lastrowid
        db.commit()
    except pymysql.err.IntegrityError:
        db.close()
        return jsonify({"success": False, "error": "El usuario ya existe"}), 409
    db.close()
    log_event("INFO", f"Admin '{session['user']}' created user '{username}' (role {role})")
    return jsonify({"success": True, "id": uid, "user_key": user_key})


@app.route("/api/users/<int:uid>/key", methods=["PUT"])
@admin_required
def set_user_key(uid):
    """Root assigns / changes a user's personal key."""
    d = request.json or {}
    new_key = d.get("key", "").strip()
    if not new_key:
        new_key = generate_user_key()
    if len(new_key) < 8:
        return jsonify({"success": False, "error": "La clave debe tener al menos 8 caracteres"}), 400
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT username FROM users WHERE id=%s", (uid,))
        row = c.fetchone()
        if not row:
            db.close()
            return jsonify({"success": False, "error": "Usuario no encontrado"}), 404
        c.execute("UPDATE users SET user_key=%s WHERE id=%s", (encrypt_db_key(new_key), uid))
    db.commit()
    db.close()
    log_event("INFO", f"Admin '{session['user']}' updated key for user '{row['username']}'")
    return jsonify({"success": True, "user_key": new_key})


@app.route("/api/users/<int:uid>", methods=["DELETE"])
@admin_required
def delete_user(uid):
    if uid == session.get("user_id"):
        return jsonify({"success": False, "error": "No puedes eliminarte a ti mismo"}), 400
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT username FROM users WHERE id=%s", (uid,))
        row = c.fetchone()
        if row:
            c.execute("DELETE FROM users WHERE id=%s", (uid,))
    db.commit()
    db.close()
    if row:
        log_event("INFO", f"Admin '{session['user']}' deleted user '{row['username']}'")
    return jsonify({"success": True})


@app.route("/")
@login_required
def index():
    return render_template("index.html")

# Connections
@app.route("/api/connections", methods=["GET"])
@login_required
def get_connections():
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT id, name, db_type, host, port, db_name, username, created_at FROM connections")
        rows = c.fetchall()
    db.close()
    result = []
    for r in rows:
        result.append({
            "id": r["id"], "name": r["name"], "db_type": r["db_type"],
            "host": r["host"], "port": r["port"], "database": r["db_name"],
            "username": r["username"], "created_at": str(r["created_at"])
        })
    return jsonify(result)

@app.route("/api/connections", methods=["POST"])
@admin_required
def add_connection():
    d = request.json
    db = get_catalog_conn()
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO connections (name, db_type, host, port, db_name, username, password) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (d["name"], d["db_type"], d.get("host",""), d.get("port", 3306),
             d.get("database",""), d.get("username",""), d.get("password",""))
        )
        conn_id = cur.lastrowid
    db.commit()
    db.close()
    log_event("INFO", f"Admin '{session['user']}' creó conexión '{d['name']}' (tipo: {d['db_type']})")
    return jsonify({"id": conn_id, "message": "Connection saved"})

@app.route("/api/connections/<int:cid>", methods=["PUT"])
@admin_required
def update_connection(cid):
    d = request.json or {}
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT name, password FROM connections WHERE id=%s", (cid,))
        existing = c.fetchone()
    if not existing:
        db.close()
        return jsonify({"success": False, "error": "Conexión no encontrada"}), 404
    # Keep existing password if not provided
    new_password = d.get("password", "").strip()
    if not new_password:
        new_password = existing["password"]
    with db.cursor() as c:
        c.execute(
            "UPDATE connections SET name=%s, db_type=%s, host=%s, port=%s, db_name=%s, username=%s, password=%s WHERE id=%s",
            (d.get("name", existing["name"]), d["db_type"], d.get("host", ""),
             d.get("port", 3306), d.get("database", ""), d.get("username", ""),
             new_password, cid)
        )
    db.commit()
    db.close()
    log_event("INFO", f"Admin '{session['user']}' editó conexión '{d.get('name', existing['name'])}' (ID: {cid})")
    return jsonify({"success": True, "message": "Conexión actualizada"})


@app.route("/api/connections/<int:cid>", methods=["DELETE"])
@admin_required
def delete_connection(cid):
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT name FROM connections WHERE id=%s", (cid,))
        row = c.fetchone()
        c.execute("DELETE FROM connections WHERE id=%s", (cid,))
    db.commit()
    db.close()
    if row:
        log_event("INFO", f"Admin '{session['user']}' eliminó conexión '{row['name']}'")
    return jsonify({"message": "Deleted"})

@app.route("/api/connections/test", methods=["POST"])
@admin_required
def test_conn():
    d = request.json
    ok, msg = test_connection(d["db_type"], d.get("host",""), d.get("port", 3306),
                               d.get("database",""), d.get("username",""), d.get("password",""))
    return jsonify({"success": ok, "message": msg})

# Backups
@app.route("/api/backups", methods=["GET"])
@login_required
def get_backups():
    conn_id = request.args.get("connection_id")
    db = get_catalog_conn()
    with db.cursor() as c:
        if conn_id:
            c.execute("""
                SELECT b.*, c.name AS connection_name
                FROM backups b
                LEFT JOIN connections c ON b.connection_id = c.id
                WHERE b.connection_id=%s
                ORDER BY b.created_at DESC
            """, (conn_id,))
        else:
            c.execute("""
                SELECT b.*, c.name AS connection_name
                FROM backups b
                LEFT JOIN connections c ON b.connection_id = c.id
                ORDER BY b.created_at DESC
            """)
        rows = c.fetchall()
    db.close()
    result = []
    for r in rows:
        result.append({
            "id": r["id"], "connection_id": r["connection_id"],
            "connection_name": r["connection_name"], "db_name": r["db_name"],
            "filename": r["filename"], "filepath": r["filepath"],
            "size_bytes": r["size_bytes"], "compressed": r["compressed"],
            "encrypted": r["encrypted"], "checksum": r["checksum"],
            "status": r["status"], "error_msg": r["error_msg"],
            "backup_type": r["backup_type"],
            "cipher_method": r.get("cipher_method") or "fernet",
            "custom_key_used": bool(r.get("custom_key_used")),
            "created_at": str(r["created_at"])
        })
    return jsonify(result)

@app.route("/api/backups", methods=["POST"])
@backup_role_required
def create_backup():
    d = request.json or {}
    user_key = d.get("user_key", "")
    if not user_key:
        return jsonify({"success": False, "error": "Se requiere tu clave personal para autorizar el backup"}), 403
    if not verify_user_key(user_key):
        log_event("WARN", f"Usuario '{session['user']}' ingresó clave personal incorrecta al crear backup")
        return jsonify({"success": False, "error": "Clave personal incorrecta"}), 403
    conn_id = d.get("connection_id")
    if not conn_id:
        return jsonify({"success": False, "error": "Selecciona una conexión"}), 400
    encrypt  = d.get("encrypt", True)
    compress = d.get("compress", True)
    cipher_method = d.get("cipher_method", "fernet")
    if cipher_method not in ("fernet", "aes-256-gcm", "chacha20"):
        return jsonify({"success": False, "error": "Método de cifrado no válido"}), 400
    custom_key = d.get("custom_key", "").strip()
    enc_password = custom_key if custom_key else user_key
    ok, result = do_backup(conn_id, encrypt, compress, enc_password, "manual",
                           cipher_method, custom_key_used=bool(custom_key))
    if ok:
        return jsonify({"success": True, "data": result})
    return jsonify({"success": False, "error": result}), 500

@app.route("/api/backups/<int:bid>", methods=["DELETE"])
@backup_role_required
def delete_backup(bid):
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT filepath FROM backups WHERE id=%s", (bid,))
        row = c.fetchone()
    if row:
        try:
            fp = Path(row["filepath"])
            if not fp.exists():
                fp = BACKUP_DIR / fp.name
            os.remove(fp)
        except:
            pass
        with db.cursor() as c:
            c.execute("DELETE FROM backups WHERE id=%s", (bid,))
        db.commit()
    db.close()
    return jsonify({"message": "Deleted"})

@app.route("/api/backups/<int:bid>/download", methods=["POST"])
@backup_role_required
def download_backup(bid):
    d = request.json or {}
    user_key       = d.get("user_key", "")
    want_decrypted = d.get("decrypt", False)

    if not verify_user_key(user_key):
        log_event("WARN", f"Usuario '{session['user']}' ingresó clave personal incorrecta al descargar backup (ID: {bid})")
        return jsonify({"error": "Clave personal incorrecta"}), 403

    dec_key = d.get("custom_key", "").strip() or user_key

    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT filepath, filename, encrypted, compressed, cipher_method FROM backups WHERE id=%s", (bid,))
        row = c.fetchone()
    db.close()
    if not row:
        return jsonify({"error": "Backup no encontrado"}), 404

    filepath = Path(row["filepath"])
    if not filepath.exists():
        filepath = BACKUP_DIR / filepath.name
    with open(filepath, "rb") as f:
        data = f.read()

    if not want_decrypted:
        log_event("INFO", f"User '{session['user']}' downloaded backup {bid} (encrypted)")
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=row["filename"], mimetype="application/octet-stream")

    cipher = row.get("cipher_method") or "fernet"
    try:
        if row["encrypted"]:
            data = decrypt_file(data, dec_key, cipher)
        if row["compressed"]:
            data = gzip.decompress(data)
    except Exception as e:
        return jsonify({"error": f"No se pudo descifrar: {str(e)}"}), 400

    plain_name = row["filename"]
    for ext in (".enc", ".gz"):
        if plain_name.endswith(ext):
            plain_name = plain_name[: -len(ext)]
    if not plain_name.endswith(".sql"):
        plain_name += ".sql"

    log_event("INFO", f"User '{session['user']}' downloaded backup {bid} (decrypted)")
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=plain_name, mimetype="text/plain")

@app.route("/api/backups/restore", methods=["POST"])
@backup_role_required
def restore_backup():
    d = request.json or {}
    user_key       = d.get("user_key", "")
    custom_key     = d.get("custom_key", "").strip()
    backup_id      = d.get("backup_id")
    target_conn_id = d.get("target_connection_id")

    if not verify_user_key(user_key):
        log_event("WARN", f"Usuario '{session['user']}' ingresó clave personal incorrecta al restaurar backup (ID: {backup_id})")
        return jsonify({"success": False, "message": "Clave personal incorrecta"}), 403

    dec_password = custom_key if custom_key else user_key
    ok, msg = do_restore(backup_id, target_conn_id, dec_password)
    return jsonify({"success": ok, "message": msg})

@app.route("/api/restores")
@login_required
def get_restores():
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute(
            "SELECT r.id, r.backup_id, r.target_conn_name, r.db_name, r.status, "
            "r.error_msg, r.created_at, u.username "
            "FROM restores r LEFT JOIN users u ON r.user_id=u.id "
            "ORDER BY r.created_at DESC LIMIT 20"
        )
        rows = c.fetchall()
    db.close()
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "backup_id": r["backup_id"],
            "target_conn_name": r["target_conn_name"],
            "db_name": r["db_name"],
            "status": r["status"],
            "error_msg": r["error_msg"],
            "created_at": r["created_at"].strftime("%d %b %Y, %H:%M") if r["created_at"] else "",
            "username": r["username"] or "—"
        })
    return jsonify(result)

@app.route("/api/backups/<int:bid>/verify", methods=["POST"])
@login_required
def verify_backup(bid):
    d = request.json or {}
    user_key = d.get("user_key", d.get("password", ""))
    custom_key = d.get("custom_key", "").strip()
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT * FROM backups WHERE id=%s", (bid,))
        row = c.fetchone()
    db.close()
    if not row:
        return jsonify({"success": False, "message": "Not found"}), 404
    try:
        with open(row["filepath"], "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return jsonify({"success": False, "message": "El archivo de backup no existe en disco"})

    checksum       = hashlib.sha256(data).hexdigest()
    checksum_match = checksum == row["checksum"]
    decrypt_ok     = None
    decrypt_msg    = None

    cipher = row.get("cipher_method") or "fernet"
    dec_password = custom_key if custom_key else user_key
    if row["encrypted"] and dec_password:
        try:
            decrypt_file(data, dec_password, cipher)
            decrypt_ok = True
        except InvalidToken:
            decrypt_ok  = False
            decrypt_msg = "Clave incorrecta: no se pudo descifrar el backup"
            log_event("WARN", f"Usuario '{session['user']}' usó clave incorrecta al verificar backup (ID: {bid})")
        except Exception as e:
            decrypt_ok  = False
            decrypt_msg = str(e) or "Error al descifrar"

    return jsonify({
        "success":       True,
        "checksum":      checksum,
        "checksum_match": checksum_match,
        "decrypt_ok":    decrypt_ok,
        "decrypt_msg":   decrypt_msg,
        "custom_key_used": bool(row.get("custom_key_used")),
        "cipher_method": cipher,
    })

# Schedules
@app.route("/api/schedules", methods=["GET"])
@login_required
def get_schedules():
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("""
            SELECT s.*, c.name as conn_name FROM schedules s
            LEFT JOIN connections c ON s.connection_id = c.id
            ORDER BY s.id DESC
        """)
        rows = c.fetchall()
    db.close()
    result = []
    for r in rows:
        result.append({
            "id": r["id"], "connection_id": r["connection_id"],
            "frequency": r["frequency"], "run_time": r.get("run_time", "00:00"),
            "encrypt": r["encrypt"],
            "compress": r["compress"], "retain_days": r["retain_days"],
            "active": r["active"], "last_run": str(r["last_run"]) if r["last_run"] else None,
            "next_run": str(r["next_run"]) if r["next_run"] else None,
            "created_at": str(r["created_at"]), "conn_name": r["conn_name"]
        })
    return jsonify(result)

def calc_next_run(freq, run_time, run_date=None):
    """Calculate next_run datetime from frequency, HH:MM time, and optional date."""
    now = datetime.now()
    try:
        h, m = [int(x) for x in run_time.split(":")]
    except Exception:
        h, m = 0, 0

    if freq == "once":
        if run_date:
            return datetime.strptime(f"{run_date} {h:02d}:{m:02d}", "%Y-%m-%d %H:%M")
        return now + timedelta(minutes=5)

    if freq == "hourly":
        nxt = now.replace(minute=m, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(hours=1)
        return nxt

    if freq == "weekly":
        nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
        nxt += timedelta(days=7)
        return nxt

    if freq == "monthly":
        day = 1
        if run_date:
            try:
                day = int(run_date)
            except (ValueError, TypeError):
                day = 1
        day = max(1, min(day, 28))
        nxt = now.replace(day=day, hour=h, minute=m, second=0, microsecond=0)
        if nxt <= now:
            month = now.month + 1
            year = now.year
            if month > 12:
                month = 1
                year += 1
            nxt = nxt.replace(year=year, month=month)
        return nxt

    if freq == "yearly":
        if run_date:
            try:
                target = datetime.strptime(f"{run_date} {h:02d}:{m:02d}", "%m-%d %H:%M")
                nxt = now.replace(month=target.month, day=target.day, hour=h, minute=m, second=0, microsecond=0)
            except Exception:
                nxt = now.replace(month=1, day=1, hour=h, minute=m, second=0, microsecond=0)
        else:
            nxt = now.replace(month=1, day=1, hour=h, minute=m, second=0, microsecond=0)
        if nxt <= now:
            nxt = nxt.replace(year=now.year + 1)
        return nxt

    # daily (default)
    nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return nxt


@app.route("/api/schedules", methods=["POST"])
@backup_role_required
def add_schedule():
    d = request.json
    freq     = d.get("frequency", "daily")
    run_time = d.get("run_time", "00:00")
    run_date = d.get("run_date")
    nxt      = calc_next_run(freq, run_time, run_date)
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("""
            INSERT INTO schedules (connection_id, frequency, run_time, encrypt, compress, retain_days, next_run)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (d["connection_id"], freq, run_time, int(d.get("encrypt", 1)),
              int(d.get("compress", 1)), d.get("retain_days", 30), nxt))
        sid = c.lastrowid
    db.commit()
    db.close()
    log_event("INFO", f"Usuario '{session['user']}' creó schedule (conexión ID: {d['connection_id']}, frecuencia: {freq}, hora: {run_time})")
    return jsonify({"id": sid, "message": "Schedule created"})

@app.route("/api/schedules/<int:sid>", methods=["PUT"])
@backup_role_required
def toggle_schedule(sid):
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT active FROM schedules WHERE id=%s", (sid,))
        row = c.fetchone()
        if row:
            c.execute("UPDATE schedules SET active=%s WHERE id=%s", (0 if row["active"] else 1, sid))
    db.commit()
    db.close()
    return jsonify({"message": "Updated"})

@app.route("/api/schedules/<int:sid>", methods=["DELETE"])
@backup_role_required
def delete_schedule(sid):
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("DELETE FROM schedules WHERE id=%s", (sid,))
    db.commit()
    db.close()
    return jsonify({"message": "Deleted"})

# Stats & Logs
@app.route("/api/stats")
@login_required
def get_stats():
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("SELECT COUNT(*) as n FROM backups WHERE status='completed'")
        total_backups = c.fetchone()["n"]
        c.execute("SELECT COALESCE(SUM(size_bytes),0) as s FROM backups WHERE status='completed'")
        total_size = c.fetchone()["s"]
        c.execute("SELECT COUNT(*) as n FROM connections")
        connections = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM backups WHERE status='failed'")
        failed = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM backups WHERE encrypted=1 AND status='completed'")
        encrypted_count = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM schedules WHERE active=1")
        schedules_active = c.fetchone()["n"]
    db.close()
    return jsonify({
        "total_backups": total_backups,
        "total_size_bytes": int(total_size),
        "connections": connections,
        "failed": failed,
        "encrypted": encrypted_count,
        "active_schedules": schedules_active
    })

@app.route("/api/conn_stats")
@login_required
def get_conn_stats():
    import time
    db = get_catalog_conn()
    with db.cursor() as c:
        t0 = time.time()
        c.execute("SELECT 1")
        conn_time_ms = round((time.time() - t0) * 1000, 2)

        c.execute("SELECT COUNT(*) as n FROM connections")
        user_connections = c.fetchone()["n"]

        c.execute(
            "SELECT COUNT(*) as n FROM logs "
            "WHERE message LIKE '%%logged in%%' AND created_at >= NOW() - INTERVAL 60 MINUTE"
        )
        logins_hour = c.fetchone()["n"]

        c.execute(
            "SELECT COUNT(*) as n FROM logs "
            "WHERE message LIKE '%%logged out%%' AND created_at >= NOW() - INTERVAL 60 MINUTE"
        )
        logouts_hour = c.fetchone()["n"]

        c.execute(
            "SELECT COUNT(*) as n FROM backups "
            "WHERE status='completed' AND created_at >= NOW() - INTERVAL 60 MINUTE"
        )
        backups_hour = c.fetchone()["n"]

        c.execute(
            "SELECT COUNT(*) as n FROM backups "
            "WHERE status='failed' AND created_at >= NOW() - INTERVAL 60 MINUTE"
        )
        failed_hour = c.fetchone()["n"]
    db.close()
    return jsonify({
        "conn_time_ms": conn_time_ms,
        "user_connections": user_connections,
        "logins_hour": logins_hour,
        "logouts_hour": logouts_hour,
        "backups_hour": backups_hour,
        "failed_hour": failed_hour
    })

@app.route("/api/system")
@login_required
def get_system_stats():
    try:
        import psutil
        cpu_pct   = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count(logical=True)
        cpu_freq  = psutil.cpu_freq()
        mem       = psutil.virtual_memory()
        disk_path = str(BASE_DIR.anchor)
        disk      = psutil.disk_usage(disk_path)
        return jsonify({
            "cpu_percent":    cpu_pct,
            "cpu_count":      cpu_count,
            "cpu_freq":       cpu_freq.current if cpu_freq else None,
            "memory_total":   mem.total,
            "memory_used":    mem.used,
            "memory_free":    mem.available,
            "memory_percent": mem.percent,
            "disk_total":     disk.total,
            "disk_used":      disk.used,
            "disk_free":      disk.free,
            "disk_percent":   disk.percent,
            "disk_path":      disk_path,
        })
    except ImportError:
        return jsonify({"error": "psutil not installed"}), 503


@app.route("/api/logs")
@login_required
def get_logs():
    role = session.get("user_role", 1)
    if role == 1:  # Lector/visitante — sin acceso a logs
        return jsonify({"error": "Acceso denegado: los visitantes no pueden ver los logs"}), 403
    db = get_catalog_conn()
    with db.cursor() as c:
        if role == 2:  # Técnico — solo sus propios logs
            c.execute("""
                SELECT l.id, l.level, l.message, l.created_at, l.ip_address, u.username
                FROM logs l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE l.user_id=%s
                ORDER BY l.created_at DESC LIMIT 200
            """, (session["user_id"],))
        else:  # Administrador — todos los logs
            c.execute("""
                SELECT l.id, l.level, l.message, l.created_at, l.ip_address, u.username
                FROM logs l
                LEFT JOIN users u ON l.user_id = u.id
                ORDER BY l.created_at DESC LIMIT 200
            """)
        rows = c.fetchall()
    db.close()
    return jsonify([{
        "id": r["id"], "level": r["level"],
        "message": r["message"], "created_at": str(r["created_at"]),
        "username": r.get("username"), "ip_address": r.get("ip_address")
    } for r in rows])

@app.route("/api/storage")
@login_required
def get_storage():
    backup_size = sum(f.stat().st_size for f in BACKUP_DIR.iterdir() if f.is_file())
    log_size = sum(f.stat().st_size for f in LOG_DIR.iterdir() if f.is_file())
    return jsonify({"backups_bytes": backup_size, "logs_bytes": log_size})


@app.route("/api/logs/export", methods=["POST"])
@login_required
def export_logs():
    role = session.get("user_role", 1)
    if role not in (0, 2):
        return jsonify({"error": "Acceso denegado"}), 403
    data = request.get_json(force=True)
    user_key = data.get("user_key", "").strip()
    if not user_key:
        return jsonify({"error": "Clave personal requerida"}), 400
    db = get_catalog_conn()
    uid = session["user_id"]
    with db.cursor() as c:
        c.execute("SELECT user_key FROM users WHERE id=%s", (uid,))
        row = c.fetchone()
    if not row or not row["user_key"]:
        db.close()
        return jsonify({"error": "No tienes clave asignada"}), 403
    stored = decrypt_db_key(row["user_key"])
    if user_key != stored:
        db.close()
        log_event("WARN", "Failed log export — wrong key", uid)
        return jsonify({"error": "Clave incorrecta"}), 403

    export_format = data.get("format", "plain")
    date_range    = data.get("range", "all")
    date_from     = data.get("date_from")
    date_to       = data.get("date_to")

    where_clauses = []
    params = []
    if role == 2:
        where_clauses.append("l.user_id=%s")
        params.append(uid)
    if date_range == "today":
        where_clauses.append("DATE(l.created_at) = CURDATE()")
    elif date_range == "range" and date_from and date_to:
        where_clauses.append("DATE(l.created_at) >= %s")
        params.append(date_from)
        where_clauses.append("DATE(l.created_at) <= %s")
        params.append(date_to)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    with db.cursor() as c:
        c.execute(f"""
            SELECT l.id, l.level, l.message, l.created_at, l.ip_address, u.username
            FROM logs l LEFT JOIN users u ON l.user_id = u.id
            {where_sql}
            ORDER BY l.created_at DESC
        """, params)
        rows = c.fetchall()
    db.close()

    lines = []
    for r in rows:
        ts = r["created_at"].strftime("%Y-%m-%d %H:%M:%S") if r["created_at"] else ""
        user = r.get("username") or "—"
        ip = r.get("ip_address") or ""
        level = (r["level"] or "INFO").upper()
        msg = r["message"] or ""
        lines.append(f"{ts}  [{level}]  {user}  {ip}  {msg}")

    plain = "\n".join(lines).encode("utf-8")
    ts_label = datetime.now().strftime("%Y%m%d_%H%M%S")

    if export_format == "encrypted":
        log_event("INFO", f"User '{session['user']}' exported logs (encrypted)", uid)
        encrypted = encrypt_file(plain, user_key)
        buf = io.BytesIO(encrypted)
        buf.seek(0)
        fname = f"logs_export_{ts_label}.log.enc"
        return send_file(buf, as_attachment=True, download_name=fname, mimetype="application/octet-stream")
    else:
        log_event("INFO", f"User '{session['user']}' exported logs (plain)", uid)
        buf = io.BytesIO(plain)
        buf.seek(0)
        fname = f"logs_export_{ts_label}.log"
        return send_file(buf, as_attachment=True, download_name=fname, mimetype="text/plain")


@app.route("/api/logs/purge", methods=["POST"])
@login_required
def purge_logs():
    role = session.get("user_role", 1)
    if role != 0:
        return jsonify({"error": "Solo administradores pueden borrar logs"}), 403
    data = request.get_json(force=True)
    days = int(data.get("days", 30))
    cutoff = datetime.now() - timedelta(days=days)
    db = get_catalog_conn()
    with db.cursor() as c:
        c.execute("DELETE FROM logs WHERE created_at < %s", (cutoff,))
        deleted = c.rowcount
    db.commit()
    db.close()
    log_event("INFO", f"Admin '{session['user']}' purged {deleted} logs older than {days} days")
    return jsonify({"success": True, "deleted": deleted})


if __name__ == "__main__":
    init_catalog()
    start_scheduler()
    start_log_writer()
    app.run(host="0.0.0.0", port=5000, use_reloader=False)

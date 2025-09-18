import sqlite3
import uuid
import random
import os
import hashlib
import hmac
import binascii
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

# =========================
# Config
# =========================
# Change DB location by editing DB_PATH or setting the BANK_DB_PATH env var.
DB_PATH = os.getenv("BANK_DB_PATH", "banking_v2.db")

# 64-bit SQLite INTEGER max (signed)
INT64_MAX = 9_223_372_036_854_775_807
MAX_BALANCE_CENTS = INT64_MAX

# =========================
# Password hashing (PBKDF2)
# =========================
ALGO = "pbkdf2_sha256"
ITERATIONS = 200_000
SALT_BYTES = 16
HASH_BYTES = 32


def _pbkdf2_hash(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=HASH_BYTES)


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    digest = _pbkdf2_hash(password, salt)
    return f"{ALGO}${ITERATIONS}${binascii.hexlify(salt).decode()}${binascii.hexlify(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations_str, salt_hex, hash_hex = stored.split("$", 3)
        if algo != ALGO:
            return False
        iterations = int(iterations_str)
        salt = binascii.unhexlify(salt_hex.encode())
        expected = binascii.unhexlify(hash_hex.encode())
        actual = _pbkdf2_hash(password, salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# =========================
# DB connection
# =========================
conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA foreign_keys = ON;")
cursor = conn.cursor()


def table_exists(name: str) -> bool:
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cursor.fetchone() is not None


def table_columns(name: str) -> list[str]:
    cursor.execute(f"PRAGMA table_info({name});")
    return [row[1] for row in cursor.fetchall()]


# =========================
# Migrations (idempotent)
# =========================
def migrate_users_table():
    # Target schema
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()

    # Old -> new: (username, password) -> (username, password_hash)
    cols = table_columns("users")
    if "password" in cols and "password_hash" not in cols:
        cursor.execute(
            """
            CREATE TABLE users_new (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
            """
        )
        cursor.execute("SELECT username, password FROM users;")
        for username, plain in cursor.fetchall():
            cursor.execute(
                "INSERT INTO users_new (username, password_hash) VALUES (?, ?)",
                (username, hash_password(plain if plain is not None else "")),
            )
        conn.commit()
        cursor.execute("DROP TABLE users;")
        cursor.execute("ALTER TABLE users_new RENAME TO users;")
        conn.commit()


def _generate_display_id() -> str:
    # 5-digit human-friendly id; uniqueness enforced in DB
    return f"{random.randint(10000, 99999)}"


def migrate_accounts_table():
    """
    Target accounts schema (P1):
      account_id TEXT PRIMARY KEY (UUIDv4)
      display_id TEXT UNIQUE NOT NULL (5-digit, human readable)
      account_holder TEXT NOT NULL
      balance_cents INTEGER NOT NULL DEFAULT 0
      user_username TEXT NULL REFERENCES users(username) ON DELETE SET NULL
    """
    # If accounts doesn't exist, create target directly
    if not table_exists("accounts"):
        cursor.execute(
            """
            CREATE TABLE accounts (
                account_id TEXT PRIMARY KEY,
                display_id TEXT NOT NULL UNIQUE,
                account_holder TEXT NOT NULL,
                balance_cents INTEGER NOT NULL DEFAULT 0,
                user_username TEXT NULL,
                FOREIGN KEY (user_username) REFERENCES users(username) ON DELETE SET NULL
            )
            """
        )
        conn.commit()
        return

    cols = set(table_columns("accounts"))
    target_cols = {"account_id", "display_id", "account_holder", "balance_cents", "user_username"}
    # If already target, nothing to do
    if target_cols.issubset(cols):
        return

    # Need to build accounts_new with target schema and copy/transform
    cursor.execute(
        """
        CREATE TABLE accounts_new (
            account_id TEXT PRIMARY KEY,
            display_id TEXT NOT NULL UNIQUE,
            account_holder TEXT NOT NULL,
            balance_cents INTEGER NOT NULL DEFAULT 0,
            user_username TEXT NULL,
            FOREIGN KEY (user_username) REFERENCES users(username) ON DELETE SET NULL
        )
        """
    )

    # Handle legacy schemas:
    # 1) Legacy had (account_number TEXT PK, account_holder TEXT, balance REAL) and optional user_username.
    #    - display_id := legacy.account_number
    #    - account_id := new UUID
    #    - balance_cents := ROUND(balance * 100) if balance exists else 0
    has_account_number = "account_number" in cols
    has_balance_real = "balance" in cols
    has_user_username = "user_username" in cols
    has_account_holder = "account_holder" in cols

    if has_account_number and has_account_holder:
        cursor.execute("SELECT account_number, account_holder {} {} FROM accounts".format(
            ", balance" if has_balance_real else "",
            ", user_username" if has_user_username else "",
        ))
        rows = cursor.fetchall()

        for row in rows:
            # Row shape depends on available columns
            if has_balance_real and has_user_username:
                old_display, holder, bal_real, owner = row
            elif has_balance_real and not has_user_username:
                old_display, holder, bal_real = row
                owner = None
            elif not has_balance_real and has_user_username:
                old_display, holder, owner = row
                bal_real = 0.0
            else:
                old_display, holder = row
                bal_real, owner = 0.0, None

            bal_cents = int(Decimal(str(bal_real)).scaleb(2).to_integral_value(rounding=ROUND_HALF_UP))
            cursor.execute(
                "INSERT OR IGNORE INTO accounts_new (account_id, display_id, account_holder, balance_cents, user_username) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), str(old_display), holder if holder else "Unnamed", bal_cents, owner),
            )
        conn.commit()

        # Replace old table
        cursor.execute("DROP TABLE accounts;")
        cursor.execute("ALTER TABLE accounts_new RENAME TO accounts;")
        conn.commit()

    else:
        # Unknown custom schema: try a safest path — copy nothing, keep empty new table
        cursor.execute("DROP TABLE accounts;")
        cursor.execute(
            """
            CREATE TABLE accounts (
                account_id TEXT PRIMARY KEY,
                display_id TEXT NOT NULL UNIQUE,
                account_holder TEXT NOT NULL,
                balance_cents INTEGER NOT NULL DEFAULT 0,
                user_username TEXT NULL,
                FOREIGN KEY (user_username) REFERENCES users(username) ON DELETE SET NULL
            )
            """
        )
        conn.commit()

    # Index for display_id already unique; additional helpful index on user_username
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_username);")
    conn.commit()


def migrate_transactions_table():
    """
    Target transactions schema (P1):
      id INTEGER PK AUTOINCREMENT
      account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE
      type TEXT NOT NULL CHECK (type IN ('DEPOSIT','WITHDRAW'))
      amount_cents INTEGER NOT NULL CHECK (amount_cents > 0)
      balance_after_cents INTEGER NOT NULL
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
      note TEXT
      INDEX (account_id, created_at)
    """
    # If doesn't exist, create target
    if not table_exists("transactions"):
        cursor.execute(
            """
            CREATE TABLE transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('DEPOSIT','WITHDRAW')),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                balance_after_cents INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                note TEXT,
                FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_txn_account_created ON transactions(account_id, created_at);")
        conn.commit()
        return

    cols = set(table_columns("transactions"))
    target_cols = {"id", "account_id", "type", "amount_cents", "balance_after_cents", "created_at", "note"}
    if target_cols.issubset(cols):
        # Ensure index exists
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_txn_account_created ON transactions(account_id, created_at);")
        conn.commit()
        return

    # We need to rebuild and convert from legacy shape.
    cursor.execute(
        """
        CREATE TABLE transactions_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('DEPOSIT','WITHDRAW')),
            amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
            balance_after_cents INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            note TEXT,
            FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
        )
        """
    )

    # Try to convert from common legacy layouts:
    # Legacy likely had: (id, account_number, type, amount REAL, balance_after REAL, created_at, note)
    has_account_number = "account_number" in cols
    has_account_id = "account_id" in cols
    has_amount_real = "amount" in cols
    has_balance_real = "balance_after" in cols

    # Build account_number -> account_id map using accounts.display_id
    account_map = {}
    if has_account_number:
        cursor.execute("SELECT account_id, display_id FROM accounts;")
        for aid, disp in cursor.fetchall():
            account_map[str(disp)] = aid

    # Copy/convert rows best-effort
    try:
        if has_account_id and has_amount_real and has_balance_real:
            cursor.execute("SELECT id, account_id, type, amount, balance_after, created_at, note FROM transactions;")
            for tid, aid, ttype, amt, bal, ts, note in cursor.fetchall():
                amt_cents = int(Decimal(str(amt)).scaleb(2).to_integral_value(rounding=ROUND_HALF_UP))
                bal_cents = int(Decimal(str(bal)).scaleb(2).to_integral_value(rounding=ROUND_HALF_UP))
                if amt_cents <= 0:
                    amt_cents = 1  # minimal positive to satisfy CHECK; legacy data cleanup
                cursor.execute(
                    "INSERT INTO transactions_new (id, account_id, type, amount_cents, balance_after_cents, created_at, note) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tid, aid, ttype, amt_cents, bal_cents, ts or datetime.utcnow().isoformat(), note),
                )
        elif has_account_number and has_amount_real and has_balance_real:
            cursor.execute("SELECT id, account_number, type, amount, balance_after, created_at, note FROM transactions;")
            for tid, disp, ttype, amt, bal, ts, note in cursor.fetchall():
                aid = account_map.get(str(disp))
                if not aid:
                    # Skip rows that reference unknown accounts (shouldn’t happen after accounts migration)
                    continue
                amt_cents = int(Decimal(str(amt)).scaleb(2).to_integral_value(rounding=ROUND_HALF_UP))
                bal_cents = int(Decimal(str(bal)).scaleb(2).to_integral_value(rounding=ROUND_HALF_UP))
                if amt_cents <= 0:
                    amt_cents = 1
                cursor.execute(
                    "INSERT INTO transactions_new (id, account_id, type, amount_cents, balance_after_cents, created_at, note) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tid, aid, ttype, amt_cents, bal_cents, ts or datetime.utcnow().isoformat(), note),
                )
        else:
            # Unknown legacy shape; skip data copy
            pass
        conn.commit()
    finally:
        cursor.execute("DROP TABLE transactions;")
        cursor.execute("ALTER TABLE transactions_new RENAME TO transactions;")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_txn_account_created ON transactions(account_id, created_at);")
        conn.commit()


# Run migrations
migrate_users_table()
migrate_accounts_table()
migrate_transactions_table()

# =========================
# Helpers (P1 types)
# =========================
def to_cents(amount_str: str) -> int:
    """Parse user input dollars to integer cents with HALF_UP rounding; rejects negatives/NaN."""
    try:
        d = Decimal(amount_str.strip())
    except (InvalidOperation, AttributeError):
        raise ValueError("Please enter a valid number.")
    if d <= 0:
        raise ValueError("Amount must be positive.")
    cents = int((d * 100).to_integral_value(rounding=ROUND_HALF_UP))
    if cents <= 0:
        raise ValueError("Amount must be positive.")
    if cents > MAX_BALANCE_CENTS:
    # prevents trying to bind a too-large integer into SQLite
        raise ValueError(f"Amount too large. Max allowed is {cents_to_str(MAX_BALANCE_CENTS)}")
    return cents


def cents_to_str(cents: int) -> str:
    d = (Decimal(cents) / Decimal(100)).quantize(Decimal("0.00"))
    return f"{d}"


def get_account_id_by_display(display_id: str) -> str | None:
    cursor.execute("SELECT account_id FROM accounts WHERE display_id = ?", (display_id,))
    row = cursor.fetchone()
    return row[0] if row else None


def account_belongs_to_user_by_display(display_id: str, username: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM accounts WHERE display_id = ? AND user_username = ?",
        (display_id, username),
    )
    return cursor.fetchone() is not None


# =========================
# Core operations (with cents & UUID)
# =========================
def create_user(username: str, password: str) -> None:
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        raise ValueError("Username already exists.")
    cursor.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    conn.commit()


def login(username: str, password: str) -> bool:
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        return False
    return verify_password(password, row[0])


def _generate_unique_display_id() -> str:
    # loop until unique
    while True:
        disp = _generate_display_id()
        cursor.execute("SELECT 1 FROM accounts WHERE display_id = ?", (disp,))
        if cursor.fetchone() is None:
            return disp


def create_account(account_holder: str, owner_username: str) -> str:
    if not owner_username:
        raise PermissionError("Must be logged in to create an account.")
    account_id = str(uuid.uuid4())
    display_id = _generate_unique_display_id()
    holder = account_holder.strip() or "Unnamed"
    cursor.execute(
        "INSERT INTO accounts (account_id, display_id, account_holder, balance_cents, user_username) "
        "VALUES (?, ?, ?, 0, ?)",
        (account_id, display_id, holder, owner_username),
    )
    conn.commit()
    return display_id  # return human-friendly id to the user


def _get_balance_cents_by_display(display_id: str) -> int | None:
    cursor.execute("SELECT balance_cents FROM accounts WHERE display_id = ?", (display_id,))
    row = cursor.fetchone()
    return int(row[0]) if row else None


def record_txn(account_id: str, ttype: str, amount_cents: int, balance_after_cents: int, note: str | None = None) -> None:
    cursor.execute(
        "INSERT INTO transactions (account_id, type, amount_cents, balance_after_cents, note) "
        "VALUES (?, ?, ?, ?, ?)",
        (account_id, ttype, amount_cents, balance_after_cents, note),
    )
    conn.commit()


def deposit(display_id: str, amount_cents: int, current_user: str) -> None:
    if amount_cents <= 0:
        raise ValueError("Amount must be positive.")
    if not account_belongs_to_user_by_display(display_id, current_user):
        raise PermissionError("You can only deposit to your own account.")
    # --- overflow guard ---
    bal = _get_balance_cents_by_display(display_id)
    if bal is None:
        raise ValueError("Account not found.")
    if bal > MAX_BALANCE_CENTS - amount_cents:
        # tell the user the exact max they can deposit right now
        raise ValueError(
            f"Deposit too large. Max you can deposit now is {cents_to_str(MAX_BALANCE_CENTS - bal)}"
        )
    # -----------------------
    
    cursor.execute("UPDATE accounts SET balance_cents = balance_cents + ? WHERE display_id = ?", (amount_cents, display_id))
    conn.commit()
    new_bal = _get_balance_cents_by_display(display_id)
    if new_bal is None:
        raise ValueError("Account not found after update.")
    aid = get_account_id_by_display(display_id)
    record_txn(aid, "DEPOSIT", amount_cents, new_bal)


def withdraw(display_id: str, amount_cents: int, current_user: str) -> bool:
    if amount_cents <= 0:
        raise ValueError("Amount must be positive.")
    if not account_belongs_to_user_by_display(display_id, current_user):
        raise PermissionError("You can only withdraw from your own account.")
    bal = _get_balance_cents_by_display(display_id)
    if bal is None:
        raise ValueError("Account not found.")
    if bal >= amount_cents:
        cursor.execute(
            "UPDATE accounts SET balance_cents = balance_cents - ? WHERE display_id = ?",
            (amount_cents, display_id),
        )
        conn.commit()
        new_bal = _get_balance_cents_by_display(display_id)
        if new_bal is None:
            raise ValueError("Account not found after update.")
        aid = get_account_id_by_display(display_id)
        record_txn(aid, "WITHDRAW", amount_cents, new_bal)
        return True
    else:
        return False


def calculate_tax(display_id: str, current_user: str) -> int:
    if not account_belongs_to_user_by_display(display_id, current_user):
        raise PermissionError("You can only view tax for your own account.")
    bal = _get_balance_cents_by_display(display_id)
    if bal is None:
        raise ValueError("Account not found.")
    # Example: 18% of balance (for demo). Using integer math, HALF_UP.
    tax = (Decimal(bal) * Decimal("0.18")).to_integral_value(rounding=ROUND_HALF_UP)
    return int(tax)


def get_account_info(display_id: str, current_user: str):
    cursor.execute(
        "SELECT display_id, account_holder, balance_cents FROM accounts WHERE display_id = ? AND user_username = ?",
        (display_id, current_user),
    )
    return cursor.fetchone()


def get_account_statement(display_id: str, current_user: str):
    if not account_belongs_to_user_by_display(display_id, current_user):
        return []
    aid = get_account_id_by_display(display_id)
    if not aid:
        return []
    cursor.execute(
        """
        SELECT id, type, amount_cents, balance_after_cents, created_at, COALESCE(note, '')
        FROM transactions
        WHERE account_id = ?
        ORDER BY datetime(created_at) ASC, id ASC
        """,
        (aid,),
    )
    return cursor.fetchall()


# =========================
# CLI
# =========================
current_user = None  # holds the username when logged in


def require_login() -> bool:
    if current_user is None:
        print("Please login first.")
        return False
    return True


def menu():
    print("\n=== Banking System Menu ===")
    print(f"User: {current_user if current_user else '(not logged in)'}")
    print("1. Register (Create User)")
    print("2. Login")
    print("3. Create Account (requires login)")
    print("4. Deposit")
    print("5. Withdraw")
    print("6. Account Information")
    print("7. Account Statement")
    print("8. Tax Payable")
    print("9. Logout")
    print("0. Exit")


def _read_positive_cents(prompt: str) -> int:
    raw = input(prompt).strip()
    return to_cents(raw)


def main():
    global current_user
    while True:
        menu()
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            try:
                username = input("New username: ").strip()
                password = input("New password: ").strip()
                create_user(username, password)
                print("User created successfully.")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "2":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            if login(username, password):
                current_user = username
                print("Login successful.")
            else:
                print("Login failed. Please check your credentials.")

        elif choice == "3":
            if not require_login():
                continue
            holder = input("Account holder's name: ").strip()
            try:
                disp = create_account(holder, current_user)
                print(f"Account created with account (display) number: {disp}")
            except PermissionError as e:
                print(f"Error: {e}")

        elif choice == "4":
            if not require_login():
                continue
            disp = input("Enter your 5-digit account display number: ").strip()
            try:
                amt_cents = _read_positive_cents("Enter amount to deposit (e.g., 100.50): ")
                deposit(disp, amt_cents, current_user)
                print("Deposit successful.")
            except (ValueError, PermissionError) as e:
                print(f"Error: {e}")

        elif choice == "5":
            if not require_login():
                continue
            disp = input("Enter your 5-digit account display number: ").strip()
            try:
                amt_cents = _read_positive_cents("Enter amount to withdraw (e.g., 20): ")
                ok = withdraw(disp, amt_cents, current_user)
                if ok:
                    print("Withdrawal successful.")
                else:
                    print("Insufficient balance.")
            except (ValueError, PermissionError) as e:
                print(f"Error: {e}")

        elif choice == "6":
            if not require_login():
                continue
            disp = input("Enter your 5-digit account display number: ").strip()
            info = get_account_info(disp, current_user)
            if info:
                display_id, holder, bal_cents = info
                print("Account Information:")
                print(f"Display Number: {display_id}")
                print(f"Account Holder: {holder}")
                print(f"Balance: {cents_to_str(bal_cents)}")
            else:
                print("Account not found (or not yours).")

        elif choice == "7":
            if not require_login():
                continue
            disp = input("Enter your 5-digit account display number: ").strip()
            rows = get_account_statement(disp, current_user)
            if rows:
                print("Account Statement:")
                for (tid, ttype, amount_cents, bal_after_cents, ts, note) in rows:
                    print(
                        f"[{ts}] #{tid} {ttype:<8} "
                        f"Amount: {cents_to_str(amount_cents)}  "
                        f"Balance After: {cents_to_str(bal_after_cents)}  {note}"
                    )
            else:
                print("No transactions found (or account not yours).")

        elif choice == "8":
            if not require_login():
                continue
            disp = input("Enter your 5-digit account display number: ").strip()
            try:
                tax_cents = calculate_tax(disp, current_user)
                print(f"Amount of TAX to be paid for available balance: {cents_to_str(tax_cents)}")
            except (ValueError, PermissionError) as e:
                print(f"Error: {e}")

        elif choice == "9":
            current_user = None
            print("Logged out.")

        elif choice == "0":
            break

        else:
            print("Invalid choice. Please try again.")

    conn.close()


if __name__ == "__main__":
    main()

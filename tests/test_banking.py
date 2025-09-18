import os
import sqlite3
import importlib
import types

def fresh_module(db_path=":memory:"):
    os.environ["BANK_DB_PATH"] = db_path
    mod = importlib.import_module("banking.app")
    importlib.reload(mod)
    return mod

def test_user_signup_and_login(tmp_path):
    db = tmp_path / "t.db"
    m = fresh_module(str(db))
    m.create_user("alice", "secret123")
    assert m.login("alice", "secret123") is True
    assert m.login("alice", "bad") is False

def test_deposit_overflow_guard(tmp_path):
    db = tmp_path / "t.db"
    m = fresh_module(str(db))
    m.create_user("bob", "pw")
    disp = m.create_account("Bob", "bob")
    # push balance near max
    almost = m.MAX_BALANCE_CENTS - 50
    m.deposit(disp, almost, "bob")
    # next deposit should be blocked
    try:
        m.deposit(disp, 100, "bob")
        assert False, "expected overflow ValueError"
    except ValueError as e:
        assert "Max you can deposit now" in str(e)

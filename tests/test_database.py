import sqlite3

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from database import PREFIX, CredentialError, SteamAccount, initialize_database

SECRET = "MDEyMzQ1Njc4OTAxMjM0NTY3ODk="


def test_migrates_legacy_plaintext_and_keeps_accounts(tmp_path):
    path = tmp_path / "accounts.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE steam_accounts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, steamid TEXT NOT NULL, steam_name TEXT, shared_secret TEXT NOT NULL, refresh_token TEXT NOT NULL, access_token TEXT, identity_secret TEXT, device_id TEXT)"
    )
    conn.execute(
        "INSERT INTO steam_accounts VALUES (1, 42, ?, ?, ?, ?, ?, ?, ?)",
        (
            "76561198000000001",
            "test",
            SECRET,
            "old-refresh-token",
            "access-token",
            SECRET,
            "android:test",
        ),
    )
    conn.commit()
    conn.close()
    key = Fernet.generate_key()
    sessions = initialize_database(path, key)
    with sessions() as session:
        account = session.scalar(select(SteamAccount))
        assert account.shared_secret == SECRET
        assert account.refresh_token == "old-refresh-token"
        account.access_token = "new-access-token"
        session.commit()
    conn = sqlite3.connect(path)
    raw = conn.execute(
        "SELECT shared_secret, refresh_token, access_token, identity_secret FROM steam_accounts"
    ).fetchone()
    assert all(value.startswith(PREFIX) for value in raw)
    assert b"old-refresh-token" not in path.read_bytes()
    assert SECRET.encode() not in path.read_bytes()
    conn.close()
    assert path.stat().st_mode & 0o777 == 0o600
    initialize_database(path, key)
    with sessions() as session:
        assert session.get(SteamAccount, 1).access_token == "new-access-token"
    with pytest.raises(CredentialError, match="不匹配"):
        initialize_database(path, Fernet.generate_key())
    initialize_database(path, key)
    with sessions() as session:
        assert session.get(SteamAccount, 1).refresh_token == "old-refresh-token"


def test_missing_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    with pytest.raises(CredentialError):
        initialize_database(tmp_path / "new.db")
    assert not (tmp_path / "new.db").exists()

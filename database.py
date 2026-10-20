"""SQLite storage, including migration of legacy plaintext credentials."""

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Column, Integer, String, create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.types import TypeDecorator

PREFIX = "enc:v1:"
SECRET_FIELDS = ("shared_secret", "identity_secret", "refresh_token", "access_token")
Base = declarative_base()


class CredentialError(RuntimeError):
    pass


class EncryptedString(TypeDecorator):
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        cipher = getattr(dialect, "_credential_cipher", None)
        if cipher is None:
            raise CredentialError("数据库加密尚未初始化。")
        return PREFIX + cipher.encrypt(value.encode()).decode()

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if not value.startswith(PREFIX):
            raise CredentialError("数据库仍有未迁移的凭据，请先运行初始化。")
        try:
            return dialect._credential_cipher.decrypt(
                value[len(PREFIX) :].encode()
            ).decode()
        except (InvalidToken, AttributeError, UnicodeError):
            raise CredentialError("无法解密凭据，请检查原有 ENCRYPTION_KEY。") from None


class SteamAccount(Base):
    __tablename__ = "steam_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)
    steamid = Column(String, nullable=False)
    steam_name = Column(String, nullable=True)
    shared_secret = Column(EncryptedString, nullable=False)
    refresh_token = Column(EncryptedString, nullable=False)
    access_token = Column(EncryptedString, nullable=True)
    identity_secret = Column(EncryptedString)
    device_id = Column(String)


def initialize_database(path=None, key=None):
    path = Path(path or os.environ.get("DATABASE_PATH", "data/steam_accounts.db"))
    try:
        cipher = Fernet(key or os.environ["ENCRYPTION_KEY"])
    except (KeyError, ValueError, TypeError):
        raise CredentialError(
            "请设置有效的 Fernet ENCRYPTION_KEY，并妥善备份。"
        ) from None
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    engine = create_engine(
        "sqlite:///" + str(path.resolve()),
        connect_args={"timeout": 15},
        hide_parameters=True,
    )
    # Each engine owns its key. Opening another database must not change this one's key.
    engine.dialect._credential_cipher = cipher

    @event.listens_for(engine, "connect")
    def configure_sqlite(connection, _):
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    migrated = False
    # The transaction rolls back all changes if any field has the wrong key.
    with engine.begin() as connection:
        rows = connection.execute(text("SELECT * FROM steam_accounts")).mappings().all()
        for row in rows:
            changes = {}
            for field in SECRET_FIELDS:
                value = row[field]
                if value is None:
                    continue
                if value.startswith(PREFIX):
                    try:
                        cipher.decrypt(value[len(PREFIX) :].encode())
                    except InvalidToken:
                        raise CredentialError(
                            "ENCRYPTION_KEY 与数据库不匹配，未修改数据。"
                        ) from None
                else:
                    changes[field] = PREFIX + cipher.encrypt(value.encode()).decode()
            if changes:
                assignments = ", ".join(f"{field} = :{field}" for field in changes)
                connection.execute(
                    text(f"UPDATE steam_accounts SET {assignments} WHERE id = :id"),
                    {**changes, "id": row["id"]},
                )
                migrated = True
    if migrated:
        with engine.connect() as connection:
            connection.exec_driver_sql("VACUUM")
    path.chmod(0o600)
    return sessionmaker(bind=engine, expire_on_commit=False)

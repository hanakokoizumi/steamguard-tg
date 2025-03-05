from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime

DATABASE_URL = "sqlite:///steam_accounts.db"
engine = create_engine(DATABASE_URL, echo=True)

Base = declarative_base()

class SharedAccount(Base):
    __tablename__ = 'shared_accounts'
    
    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('steam_accounts.id', ondelete='CASCADE'))
    shared_user_id = Column(String)  # Telegram user ID
    can_confirm_market = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    account = relationship("SteamAccount", back_populates="shared_with")

class SteamAccount(Base):
    __tablename__ = 'steam_accounts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)
    steamid = Column(String, nullable=False)
    steam_name = Column(String, nullable=True)
    shared_secret = Column(String, nullable=False)
    refresh_token = Column(String, nullable=False)
    access_token = Column(String, nullable=True)
    identity_secret = Column(String)
    device_id = Column(String)
    
    shared_with = relationship("SharedAccount", back_populates="account", cascade="all, delete-orphan")

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

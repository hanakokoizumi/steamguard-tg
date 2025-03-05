from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///steam_accounts.db"
engine = create_engine(DATABASE_URL, echo=True)

Base = declarative_base()

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

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

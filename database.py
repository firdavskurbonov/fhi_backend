from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from decouple import config

POSTGRES_USER = config('POSTGRES_USER')
POSTGRES_PASSWORD = config('POSTGRES_PASSWORD')
POSTGRES_DB = config('POSTGRES_DB')
POSTGRES_PORT = config('POSTGRES_PORT')
POSTGRES_HOST = config('POSTGRES_HOST')


# PostgreSQL connection URL
DATABASE_URL = "postgresql://" + POSTGRES_USER+":"+POSTGRES_PASSWORD + \
    "@"+POSTGRES_HOST+":"+POSTGRES_PORT+"/"+POSTGRES_DB
# Create a PostgreSQL engine instance
engine = create_engine(DATABASE_URL)
# Create declarative base meta instance
Base = declarative_base()
# Create session local class for session maker
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

# Ensure the 'database' folder exists one level above the current (src) directory
os.makedirs("../database", exist_ok=True)

DATABASE_URL = "sqlite:///../database/scan_results.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Create tables
def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database initialized and tables created.")
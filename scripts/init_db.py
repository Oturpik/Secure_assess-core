"""
Initialize database tables.
"""

import asyncio
import logging
import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.db.postgres.models import Base
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.sql import text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_db():
    """Initialize database tables."""
    try:
        # Create async engine
        database_url = os.getenv("DATABASE_URL", "postgresql://scanner_user:postgres@localhost:5432/security_scanner")
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
        
        engine = create_async_engine(
            database_url,
            echo=True
        )
        
        # First connect as the postgres superuser
        admin_database_url = database_url.replace("scanner_user:postgres", "postgres:postgres")
        admin_engine = create_async_engine(admin_database_url)
        
        async with admin_engine.begin() as conn:
            # Grant schema usage to scanner_user
            await conn.execute(text("GRANT USAGE ON SCHEMA public TO scanner_user;"))
            # Grant all privileges on all tables in public schema to scanner_user
            await conn.execute(text("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scanner_user;"))
            # Grant all privileges on all sequences in public schema to scanner_user
            await conn.execute(text("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scanner_user;"))
            # Allow scanner_user to create tables
            await conn.execute(text("GRANT CREATE ON SCHEMA public TO scanner_user;"))
        
        logger.info("Database permissions granted successfully")
        
        # Create all tables using scanner_user
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(init_db())

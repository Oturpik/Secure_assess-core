"""
Add missing columns to scan_results table for framework-aware scanning.
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine, text
from src.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)

def add_missing_columns():
    """Add findings_by_category, category_scores, scanned_categories columns."""
    
    engine = create_engine(settings.database_url)
    
    with engine.begin() as conn:
        try:
            # Check existing columns
            result = conn.execute(
                text("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name='scan_results'
                """)
            )
            existing_cols = [row[0] for row in result.fetchall()]
            logger.info(f"Existing columns in scan_results: {existing_cols}")
            
            # Add findings_by_category
            if 'findings_by_category' not in existing_cols:
                logger.info("Adding findings_by_category column...")
                conn.execute(text(
                    'ALTER TABLE scan_results ADD COLUMN findings_by_category JSONB DEFAULT NULL'
                ))
                logger.info("✓ Added findings_by_category")
            else:
                logger.info("✓ findings_by_category already exists")
            
            # Add category_scores
            if 'category_scores' not in existing_cols:
                logger.info("Adding category_scores column...")
                conn.execute(text(
                    'ALTER TABLE scan_results ADD COLUMN category_scores JSONB DEFAULT NULL'
                ))
                logger.info("✓ Added category_scores")
            else:
                logger.info("✓ category_scores already exists")
            
            # Add scanned_categories
            if 'scanned_categories' not in existing_cols:
                logger.info("Adding scanned_categories column...")
                conn.execute(text(
                    'ALTER TABLE scan_results ADD COLUMN scanned_categories JSONB DEFAULT NULL'
                ))
                logger.info("✓ Added scanned_categories")
            else:
                logger.info("✓ scanned_categories already exists")
            
            logger.info("✅ All required columns are now present!")
            
        except Exception as e:
            logger.error(f"Error adding columns: {str(e)}")
            raise

if __name__ == "__main__":
    logger.info("Starting column addition...")
    add_missing_columns()
    logger.info("Column addition complete!")

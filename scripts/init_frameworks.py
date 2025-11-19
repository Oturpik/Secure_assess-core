"""
Initialize security frameworks and their categories in the database.
This script populates the frameworks table with OWASP Top 10, CIS, and NIST 800-53.
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.config import settings
from src.db.postgres.models import Base, Framework, Control, ComplianceRequirement
from src.services.compliance.framework_categories import (
    OWASP_CATEGORIES, CIS_CATEGORIES, NIST_CATEGORIES, FrameworkType
)
from src.core.logging import get_logger

logger = get_logger(__name__)


def initialize_frameworks():
    """Initialize frameworks with categories in the database."""
    
    # Create engine and tables
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(engine)
    
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Check if frameworks already exist
        owasp_exists = session.query(Framework).filter(Framework.name == "OWASP").first()
        cis_exists = session.query(Framework).filter(Framework.name == "CIS").first()
        nist_exists = session.query(Framework).filter(Framework.name == "NIST").first()
        
        # If OWASP exists but has no categories, add them
        if owasp_exists:
            owasp_controls = session.query(Control).filter(Control.framework_id == owasp_exists.id).count()
            if owasp_controls == 0:
                logger.info("OWASP exists but has no categories. Adding them...")
                for cat_key, category_def in OWASP_CATEGORIES.items():
                    existing = session.query(Control).filter(
                        Control.framework_id == owasp_exists.id,
                        Control.control_id == category_def.id
                    ).first()
                    if not existing:
                        control = Control(
                            framework_id=owasp_exists.id,
                            control_id=category_def.id,
                            title=category_def.name,
                            description=category_def.description,
                            category=category_def.name,
                            severity=category_def.priority,
                            subcategory="Web Application"
                        )
                        session.add(control)
                session.commit()
                logger.info(f"✓ OWASP categories added: {len(OWASP_CATEGORIES)}")
        
        if cis_exists and nist_exists:
            if owasp_exists:
                logger.info("All frameworks already initialized. Skipping initialization.")
                return
        
        # Initialize OWASP Top 10
        if not owasp_exists:
            logger.info("Initializing OWASP Top 10 framework...")
            owasp_framework = Framework(
                name="OWASP",
                version="2025",
                description="OWASP Top 10 2025 - The 10 Most Critical Web Application Security Risks"
            )
            session.add(owasp_framework)
            session.flush()
            
            # Add OWASP categories as controls
            for cat_key, category_def in OWASP_CATEGORIES.items():
                control = Control(
                    framework_id=owasp_framework.id,
                    control_id=category_def.id,
                    title=category_def.name,
                    description=category_def.description,
                    category=category_def.name,
                    severity=category_def.priority,
                    subcategory="Web Application"
                )
                session.add(control)
            
            logger.info(f"✓ OWASP Top 10 framework initialized with {len(OWASP_CATEGORIES)} categories")
        
        # Initialize CIS Framework
        if not cis_exists:
            logger.info("Initializing CIS (Center for Internet Security) framework...")
            cis_framework = Framework(
                name="CIS",
                version="1.0",
                description="Center for Internet Security (CIS) Framework - Application Security Standards"
            )
            session.add(cis_framework)
            session.flush()
            
            # Add CIS categories as controls
            for cat_key, category_def in CIS_CATEGORIES.items():
                control = Control(
                    framework_id=cis_framework.id,
                    control_id=category_def.id,
                    title=category_def.name,
                    description=category_def.description,
                    category=category_def.name,
                    severity=category_def.priority,
                    subcategory="Software Security"
                )
                session.add(control)
            
            logger.info(f"✓ CIS framework initialized with {len(CIS_CATEGORIES)} categories")
        
        # Initialize NIST 800-53
        if not nist_exists:
            logger.info("Initializing NIST 800-53 framework...")
            nist_framework = Framework(
                name="NIST",
                version="Rev. 5",
                description="NIST SP 800-53 - Security and Privacy Controls for Federal Information Systems"
            )
            session.add(nist_framework)
            session.flush()
            
            # Add NIST categories as controls
            for cat_key, category_def in NIST_CATEGORIES.items():
                control = Control(
                    framework_id=nist_framework.id,
                    control_id=category_def.id,
                    title=category_def.name,
                    description=category_def.description,
                    category=category_def.name,
                    severity=category_def.priority,
                    subcategory="System Security"
                )
                session.add(control)
            
            logger.info(f"✓ NIST 800-53 framework initialized with {len(NIST_CATEGORIES)} categories")
        
        session.commit()
        logger.info("✓ All frameworks initialized successfully!")
        
        # Print summary
        print("\n" + "="*70)
        print("FRAMEWORK INITIALIZATION SUMMARY")
        print("="*70)
        
        frameworks = session.query(Framework).all()
        for fw in frameworks:
            controls_count = session.query(Control).filter(Control.framework_id == fw.id).count()
            print(f"\n{fw.name} (v{fw.version})")
            print(f"  Categories: {controls_count}")
            print(f"  Description: {fw.description}")
        
        print("\n" + "="*70)
        print("\nFrameworks initialized. You can now use them in your scans:")
        print("  - framework_id=1 for OWASP Top 10")
        print("  - framework_id=2 for CIS Framework")
        print("  - framework_id=3 for NIST 800-53")
        
    except Exception as e:
        logger.error(f"Error initializing frameworks: {str(e)}")
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    logger.info("Starting framework initialization...")
    initialize_frameworks()
    logger.info("Framework initialization complete!")

"""
Test script to run a sample SAST scan.
"""

import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.config import settings
from src.services.scanning.orchestrator import ScanOrchestrator
from src.core.logging import get_logger

logger = get_logger(__name__)

def run_test_scan():
    """Run a test SAST scan on a sample repository."""
    # Create database session
    engine = create_engine(settings.database_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Initialize orchestrator
        orchestrator = ScanOrchestrator(session)
        
        # Start a scan
        repo_url = "https://github.com/Oturpik/Secure_assess-core.git"  # Example repo
        scan_id = orchestrator.initiate_scan(
            repository_url=repo_url,
            branch="main",
            framework_id=1,  # Assuming OWASP framework is ID 1
            scan_types=["sast"],
            priority=5
        )
        
        logger.info(f"Started scan {scan_id}")
        
        # Monitor scan progress
        while True:
            status = orchestrator.get_scan_status(scan_id)
            logger.info(f"Scan status: {status['status']}")
            
            if status['status'] in ['complete', 'failed']:
                break
                
            time.sleep(10)  # Check every 10 seconds
        
        # Get final results
        if status['status'] == 'complete':
            logger.info("Scan completed successfully")
            logger.info(f"Findings: {status['findings']}")
            logger.info(f"Compliance score: {status['compliance_score']}")
        else:
            logger.error("Scan failed")
            
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        raise
        
    finally:
        session.close()

if __name__ == "__main__":
    logger.info("Starting test scan...")
    run_test_scan()
from fastapi import UploadFile, HTTPException
from pathlib import Path
import tempfile
import shutil
import zipfile
import tarfile
from typing import Optional, Dict, Any
import os

from src.core.logging import get_logger
from src.services.scanning.orchestrator import ScanOrchestrator
from src.db.session import get_db

logger = get_logger(__name__)

class CodeUploadHandler:
    def __init__(self):
        self.temp_dir = None
        
    async def handle_upload(
        self,
        file: UploadFile,
        framework_id: int,
        scan_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Handle uploaded code files for scanning.
        
        Args:
            file: Uploaded file (ZIP or TAR)
            framework_id: ID of the compliance framework to use
            scan_name: Optional name for the scan
            
        Returns:
            Dict containing scan_id and status
        """
        try:
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp(prefix="scan_")
            
            # Get file extension
            file_ext = Path(file.filename).suffix.lower()
            
            # Save uploaded file
            temp_file = Path(self.temp_dir) / file.filename
            with temp_file.open("wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            # Extract files
            extract_dir = Path(self.temp_dir) / "code"
            extract_dir.mkdir()
            
            if file_ext == ".zip":
                with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif file_ext in [".tar", ".gz", ".tgz"]:
                with tarfile.open(temp_file, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Unsupported file format. Please upload ZIP or TAR archives."
                )
            
            # Initialize scan
            db = next(get_db())
            orchestrator = ScanOrchestrator(db)
            
            # Create a virtual repository URL for local files
            virtual_repo_url = f"file://{extract_dir}"
            
            # Start SAST scan
            scan_id = await orchestrator.initiate_scan(
                repository_url=virtual_repo_url,
                branch="main",  # Default for uploaded files
                framework_id=framework_id,
                scan_types=["sast"],  # Only SAST for now
                priority=5
            )
            
            return {
                "scan_id": scan_id,
                "status": "initiated",
                "scan_name": scan_name or file.filename
            }
            
        except Exception as e:
            logger.error(f"Failed to process uploaded file: {str(e)}")
            raise
            
        finally:
            # Cleanup will be handled by cleanup_worker
            pass
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None
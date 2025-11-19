import json
import subprocess
import tempfile
from typing import Dict, Any, Optional
import os
from git import Repo

from src.core.logging import get_logger

logger = get_logger(__name__)

class SemgrepScanner:
    def scan_repository(
        self,
        repository_url: str,
        branch: str,
        rules: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Scan a Git repository using Semgrep.
        
        Args:
            repository_url: URL of the repository to scan
            branch: Branch to scan
            rules: Optional custom Semgrep rules to apply
            
        Returns:
            Dict containing scan results
        """
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone repository
                logger.info(f"Cloning {repository_url}:{branch} to {temp_dir}")
                repo = Repo.clone_from(repository_url, temp_dir, branch=branch)
                
                # Write rules if provided
                rules_file = None
                if rules:
                    rules_file = os.path.join(temp_dir, "semgrep-rules.yaml")
                    with open(rules_file, 'w') as f:
                        json.dump(rules, f)
                
                # Build Semgrep command
                cmd = [
                    "semgrep",
                    "--json",    # JSON output
                    "--quiet",   # Less verbose output
                    "-a",        # Run all rules
                ]
                
                # Add rules file if provided
                if rules_file:
                    cmd.extend(["--config", rules_file])
                else:
                    cmd.extend(["--config", "auto"])  # Use default rules
                    
                cmd.append(".")  # Scan current directory
                
                logger.info("Running Semgrep scan")
                process = subprocess.run(
                    cmd,
                    cwd=temp_dir,
                    capture_output=True,
                    text=True
                )
                
                # Parse results
                try:
                    raw_output = json.loads(process.stdout)
                except json.JSONDecodeError:
                    logger.error("Failed to parse Semgrep output")
                    raw_output = {}
                
                # Process results
                issues = []
                for result in raw_output.get("results", []):
                    issues.append({
                        "severity": result.get("extra", {}).get("severity", "unknown"),
                        "confidence": "high",  # Semgrep doesn't provide confidence
                        "type": result.get("check_id", "unknown"),
                        "file": result.get("path", "unknown"),
                        "line": result.get("start", {}).get("line", 0),
                        "code": result.get("extra", {}).get("lines", ""),
                        "message": result.get("extra", {}).get("message", "")
                    })
                
                return {
                    "issues": issues,
                    "metrics": {
                        "total_files": len(raw_output.get("paths", {}).get("scanned", [])),
                        "total_lines": sum(len(i.get("extra", {}).get("lines", "").split("\n"))
                                        for i in raw_output.get("results", [])),
                        "high_severity": len([i for i in issues if i["severity"] == "ERROR"]),
                        "medium_severity": len([i for i in issues if i["severity"] == "WARNING"]),
                        "low_severity": len([i for i in issues if i["severity"] == "INFO"])
                    },
                    "raw_output": raw_output
                }
                
        except Exception as e:
            logger.error(f"Semgrep scan failed: {str(e)}")
            raise

import json
import subprocess
import tempfile
from typing import Dict, Any, Optional
import os
from git import Repo

from src.core.logging import get_logger

logger = get_logger(__name__)

class BanditScanner:
    def scan_repository(
        self,
        repository_url: str,
        branch: str,
        custom_rules: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Scan a Git repository using Bandit.
        
        Args:
            repository_url: URL of the repository to scan
            branch: Branch to scan
            custom_rules: Optional custom Bandit rules to apply
            
        Returns:
            Dict containing scan results
        """
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone repository
                logger.info(f"Cloning {repository_url}:{branch} to {temp_dir}")
                repo = Repo.clone_from(repository_url, temp_dir, branch=branch)
                
                # Write custom rules if provided
                rules_file = None
                if custom_rules:
                    rules_file = os.path.join(temp_dir, "custom_rules.json")
                    with open(rules_file, 'w') as f:
                        json.dump(custom_rules, f)
                
                # Run Bandit scan
                cmd = [
                    "bandit",
                    "-r",      # Recursive scan
                    ".",       # Current directory
                    "-f",      # Output format
                    "json"     # JSON output
                ]
                
                # Add custom rules if provided
                if rules_file:
                    cmd.extend([
                        "--config",
                        rules_file
                    ])
                
                logger.info("Running Bandit scan")
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
                    logger.error("Failed to parse Bandit output")
                    raw_output = {}
                
                # Process results
                issues = []
                for result in raw_output.get("results", []):
                    issues.append({
                        "severity": result.get("issue_severity", "unknown"),
                        "confidence": result.get("issue_confidence", "unknown"),
                        "type": result.get("issue_text", "unknown"),
                        "file": result.get("filename", "unknown"),
                        "line": result.get("line_number", 0),
                        "code": result.get("code", ""),
                        "description": result.get("issue_text", "")
                    })
                
                return {
                    "issues": issues,
                    "metrics": {
                        "total_files": raw_output.get("metrics", {}).get("_totals", {}).get("CONFIDENCE.HIGH", 0),
                        "total_lines": raw_output.get("metrics", {}).get("_totals", {}).get("loc", 0),
                        "high_severity": len([i for i in issues if i["severity"] == "HIGH"]),
                        "medium_severity": len([i for i in issues if i["severity"] == "MEDIUM"]),
                        "low_severity": len([i for i in issues if i["severity"] == "LOW"])
                    },
                    "raw_output": raw_output
                }
                
        except Exception as e:
            logger.error(f"Bandit scan failed: {str(e)}")
            raise

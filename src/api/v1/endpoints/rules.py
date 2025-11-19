from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from src.db.session import get_db
from src.services.scanning.rules_manager import RulesManager

router = APIRouter()

@router.get("/frameworks")
async def list_frameworks(db: Session = Depends(get_db)):
    """
    List all available compliance frameworks and their rules status
    """
    rules_manager = RulesManager(db)
    return rules_manager.get_available_frameworks()

@router.post("/frameworks/{framework_id}/rules/generate")
async def generate_framework_rules(
    framework_id: int,
    db: Session = Depends(get_db)
):
    """
    Generate scanner rules for a specific framework
    """
    try:
        rules_manager = RulesManager(db)
        rules = rules_manager.get_framework_rules(framework_id)
        return {
            "status": "success",
            "message": f"Rules generated for framework {rules['framework_name']}",
            "rules_summary": {
                "bandit_rules": len(rules["bandit"]["custom_rules"]),
                "semgrep_rules": len(rules["semgrep"]["rules"])
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate rules: {str(e)}"
        )

@router.get("/frameworks/{framework_id}/rules")
async def get_framework_rules(
    framework_id: int,
    db: Session = Depends(get_db)
):
    """
    Get the current rules for a framework
    """
    try:
        rules_manager = RulesManager(db)
        return rules_manager.get_framework_rules(framework_id)
    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Rules not found: {str(e)}"
        )

@router.get("/scan/preview")
async def preview_scan_rules(
    framework_id: int,
    repository_url: str,
    branch: str = "main",
    db: Session = Depends(get_db)
):
    """
    Preview which rules would apply to a repository without running a full scan
    """
    try:
        rules_manager = RulesManager(db)
        rules = rules_manager.get_framework_rules(framework_id)
        
        # Extract rule summaries
        bandit_rules = [
            {
                "id": rule_id,
                "message": rule["message"],
                "severity": rule["severity"],
                "type": rule["type"]
            }
            for rule_id, rule in rules["bandit"]["custom_rules"].items()
        ]
        
        semgrep_rules = [
            {
                "id": rule["id"],
                "message": rule["message"],
                "severity": rule["severity"],
                "category": rule["metadata"]["category"]
            }
            for rule in rules["semgrep"]["rules"]
        ]
        
        return {
            "framework": rules["framework_name"],
            "repository": repository_url,
            "branch": branch,
            "rules_summary": {
                "bandit": {
                    "total_rules": len(bandit_rules),
                    "rules": bandit_rules
                },
                "semgrep": {
                    "total_rules": len(semgrep_rules),
                    "rules": semgrep_rules
                }
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to preview rules: {str(e)}"
        )
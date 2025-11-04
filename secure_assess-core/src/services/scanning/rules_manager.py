from typing import Dict, List, Any, Optional, cast
from pathlib import Path
import yaml
import json
from sqlalchemy.orm import Session
from sqlalchemy import Column

from src.db.postgres.models import Framework, Control
from src.core.logging import get_logger

logger = get_logger(__name__)

class RulesManager:
    def __init__(self, db: Session):
        self.db = db
        self.rules_dir = Path(__file__).parent / "rules"
        self.rules_dir.mkdir(exist_ok=True)
        
    def get_framework_rules(self, framework_id: int) -> Dict[str, Any]:
        """
        Get scanner rules specific to a compliance framework.
        
        Args:
            framework_id: ID of the framework to get rules for
            
        Returns:
            Dict containing Bandit and Semgrep rules
        """
        framework = self.db.query(Framework).filter(
            Framework.id == framework_id
        ).first()
        
        if not framework:
            raise ValueError(f"Framework with ID {framework_id} not found")
            
        # Get framework controls
        controls = self.db.query(Control).filter(
            Control.framework_id == framework_id
        ).all()
        
        # Generate rules for each scanner
        bandit_rules = self._generate_bandit_rules(framework, controls)
        semgrep_rules = self._generate_semgrep_rules(framework, controls)
        
        return {
            "bandit": bandit_rules,
            "semgrep": semgrep_rules,
            "framework_name": framework.name
        }
    
    def _generate_bandit_rules(
        self,
        framework: Framework,
        controls: List[Control]
    ) -> Dict[str, Any]:
        """Generate Bandit rules from framework controls"""
        rules = {
            "profiles": {
                framework.name.lower(): {
                    "include": []
                }
            },
            "custom_rules": {}
        }
        
        for control in controls:
            rule_id = f"{framework.name.lower()}_{control.control_id}"
            
            # Map control categories to Bandit test types
            if "injection" in control.category.lower():
                test_type = "blacklist"
            elif "authentication" in control.category.lower():
                test_type = "auth"
            elif "crypto" in control.category.lower():
                test_type = "crypto"
            else:
                test_type = "misc"
            
            rule = {
                "id": rule_id,
                "message": control.title,
                "type": test_type,
                "severity": str(control.severity).lower() if control.severity is not None else "medium",
                "description": control.description,
                "patterns": self._extract_patterns(control)
            }
            
            rules["custom_rules"][rule_id] = rule
            rules["profiles"][framework.name.lower()]["include"].append(rule_id)
        
        # Save rules to file
        rules_file = self.rules_dir / f"bandit_{framework.name.lower()}.json"
        with open(rules_file, 'w') as f:
            json.dump(rules, f, indent=2)
            
        return rules
    
    def _generate_semgrep_rules(
        self,
        framework: Framework,
        controls: List[Control]
    ) -> Dict[str, Any]:
        """Generate Semgrep rules from framework controls"""
        rules = {
            "rules": []
        }
        
        for control in controls:
            rule_id = f"{framework.name.lower()}-{control.control_id}"
            
            # Convert control requirements into Semgrep patterns
            patterns = self._extract_patterns(control)
            
            rule = {
                "id": rule_id,
                "pattern": " pattern: |\n    " + "\n    ".join(patterns),
                "message": control.title,
                "severity": str(control.severity).lower() if control.severity is not None else "WARNING",
                "metadata": {
                    "framework": framework.name,
                    "category": control.category,
                    "description": control.description
                }
            }
            
            rules["rules"].append(rule)
        
        # Save rules to file
        rules_file = self.rules_dir / f"semgrep_{framework.name.lower()}.yaml"
        with open(rules_file, 'w') as f:
            yaml.safe_dump(rules, f)
            
        return rules
    
    def _extract_patterns(self, control: Control) -> List[str]:
        """Extract patterns from control description and criteria"""
        patterns = []
        
        # Common security patterns based on control category
        if control.category is not None:
            category = control.category.lower()
            
            if "injection" in category:
                patterns.extend([
                    "exec(",
                    "eval(",
                    "subprocess.run(",
                    "os.system(",
                ])
            elif "authentication" in category:
                patterns.extend([
                    "password",
                    "secret",
                    "token",
                    "api_key",
                ])
            elif "crypto" in category:
                patterns.extend([
                    "md5",
                    "sha1",
                    "random.random(",
                    "math.random(",
                ])
            elif "access control" in category:
                patterns.extend([
                    "chmod(",
                    "os.chmod(",
                    "permission",
                    "privilege",
                ])
        
        # Add patterns from validation criteria if available
        if hasattr(control, 'validation_criteria') and control.validation_criteria:
            try:
                criteria = json.loads(control.validation_criteria)
                if isinstance(criteria, dict):
                    patterns.extend(criteria.get('patterns', []))
            except json.JSONDecodeError:
                pass
        
        return patterns

    def get_available_frameworks(self) -> List[Dict[str, Any]]:
        """Get list of available frameworks with their rules"""
        frameworks = self.db.query(Framework).all()
        
        return [{
            "id": fw.id,
            "name": fw.name,
            "version": fw.version,
            "description": fw.description,
            "rules_status": self._check_rules_status(fw)
        } for fw in frameworks]
    
    def _check_rules_status(self, framework: Framework) -> Dict[str, bool]:
        """Check if rules files exist for a framework"""
        bandit_rules = self.rules_dir / f"bandit_{framework.name.lower()}.json"
        semgrep_rules = self.rules_dir / f"semgrep_{framework.name.lower()}.yaml"
        
        return {
            "bandit": bandit_rules.exists(),
            "semgrep": semgrep_rules.exists()
        }
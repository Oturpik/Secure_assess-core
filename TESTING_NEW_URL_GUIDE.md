# 📖 Complete Guide: Testing a New Repository URL

## Quick Start

```bash
# Test with default OWASP framework
python scripts/test_new_url.py https://github.com/user/repo.git

# Test with CIS framework
python scripts/test_new_url.py https://github.com/user/repo.git --framework 2

# Test specific branch with NIST framework
python scripts/test_new_url.py https://github.com/user/repo.git --branch develop --framework 3

# Export results to JSON
python scripts/test_new_url.py https://github.com/user/repo.git --export results.json
```

---

## Complete Workflow Breakdown

### **STEP 1: View Available Frameworks**

Before submitting a scan, see what frameworks are available:

```bash
python scripts/test_new_url.py --list-frameworks
```

**Output:**
```
============================================================
AVAILABLE COMPLIANCE FRAMEWORKS
============================================================

📋 OWASP (ID: 1)
   Version: 4.0
   Categories: 10
     - A01: Broken Access Control
     - A02: Cryptographic Failures
     - A03: Injection
     ... and 7 more

📋 CIS (ID: 2)
   Version: 1.0
   Categories: 2
     - CIS-AS: Application Software Security
     - CIS-AC: Access Control Management

📋 NIST (ID: 3)
   Version: Revision 5
   Categories: 5
     - NIST-IA: Identification and Authentication
     - NIST-AC: Access Control
     ... and 3 more
```

### **STEP 2: Submit a New Repository**

Submit your repository URL for scanning:

```bash
python scripts/test_new_url.py https://github.com/example/myapp.git
```

**What happens:**
1. Script validates the repository URL
2. Creates a database record for the scan
3. Submits to the scanning orchestrator
4. Returns a unique **Scan ID** for tracking

**Output:**
```
============================================================
STEP 1: SUBMITTING SCAN REQUEST
============================================================
📍 Repository: https://github.com/example/myapp.git
🌿 Branch: main
📋 Framework: 1

✅ Scan submitted successfully!
   Scan ID: 550e8400-e29b-41d4-a716-446655440000
```

### **STEP 3: Monitor Scan Progress**

The script automatically monitors your scan:

```
============================================================
STEP 2: MONITORING SCAN PROGRESS
============================================================
⏳ Check #1 (Elapsed: 0s) - Status: PENDING
⏳ Check #2 (Elapsed: 10s) - Status: IN_PROGRESS
⏳ Check #3 (Elapsed: 20s) - Status: IN_PROGRESS
...
⏳ Check #15 (Elapsed: 140s) - Status: IN_PROGRESS

✅ Scan completed successfully!
```

**Behind the scenes during scan:**
1. Repository cloned locally
2. Bandit scanner runs (Python security issues)
3. Semgrep scanner runs (code patterns & vulnerabilities)
4. CategoryCheckRunner categorizes findings
5. Compliance scores calculated per category
6. Results stored in database

**Timeline:** Usually 1-3 minutes depending on repository size

### **STEP 4: Review Categorized Results**

Once complete, results are displayed by framework category:

```
============================================================
STEP 4: FRAMEWORK-SPECIFIC RESULTS (Framework 1)
============================================================

📊 CATEGORY SCORES (OWASP):
   ✅ A01: 100.0% [██████████]
   ✅ A02: 100.0% [██████████]
   ⚠️  A03:  85.0% [████████░░] ← Issues found here
   ✅ A04: 100.0% [██████████]
   ...

🔍 FINDINGS BY CATEGORY:

   📌 A03: 1 finding(s)
      • CRITICAL: Possible SQL injection vector through string-based query construction
         File: src/api/database.py, Line 105
      
   📌 A07: 2 finding(s)
      • HIGH: Possible insecure hash function used
         File: src/auth/password.py, Line 42
      
✓ CATEGORIES SCANNED: 10
   A01, A02, A03, A04, A05, A06, A07, A08, A09, A10
```

---

## Understanding the Results

### **Compliance Score: What It Means**

- **90-100%**: ✅ Excellent - Few or no critical issues
- **70-89%**: ⚠️ Good - Some issues to address
- **50-69%**: 🔴 Fair - Significant security concerns
- **Below 50%**: 🚨 Critical - Immediate action needed

### **Category Score Calculation**

Each category is scored based on:
- **Number of vulnerabilities** in that category
- **Severity levels** (critical = worst, low = best)
- **Type of issues** (how directly they relate to the category)

**Example:** 
- A03 (Injection) with 0 findings = 100%
- A03 with 1 critical finding = 85%
- A03 with 3 critical findings = 60%

### **Framework Differences**

Same codebase, different categorizations:

**OWASP Focus:**
```
A03 (Injection): SQL injection found ✓
A02 (Crypto): Weak hash function found ✓
A01 (Access Control): Privilege escalation found ✓
```

**CIS Focus:**
```
CIS-AS (App Security): All three issues grouped here ✓
CIS-AC (Access Control): Only privilege escalation here ✓
```

**NIST Focus:**
```
NIST-IA (Auth): Weak hash grouped here ✓
NIST-AC (Access): Privilege escalation here ✓
NIST-SI (System Integrity): SQL injection here ✓
```

---

## Advanced Usage

### **Test Multiple Frameworks**

Compare how the same repository scores across frameworks:

```bash
# OWASP scan
python scripts/test_new_url.py https://github.com/example/repo.git --framework 1

# CIS scan
python scripts/test_new_url.py https://github.com/example/repo.git --framework 2

# NIST scan
python scripts/test_new_url.py https://github.com/example/repo.git --framework 3
```

This allows you to see:
- Which framework is most relevant to your use case
- How findings map differently across standards
- Complete compliance picture with all frameworks

### **Export Results**

Save results to JSON for:
- Frontend integration
- Reporting automation
- Historical comparison
- Third-party tools

```bash
python scripts/test_new_url.py https://github.com/example/repo.git \
  --export scan_results_2025_11_19.json
```

**JSON Output Structure:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "framework_id": 1,
  "repository_url": "https://github.com/example/repo.git",
  "branch": "main",
  "scan_date": "2025-11-19T10:30:00",
  "status": "complete",
  "compliance_score": 85.5,
  "findings_by_category": {
    "A01": { "findings": [...] },
    "A02": { "findings": [...] },
    "A03": { "findings": [...] }
  },
  "category_scores": {
    "A01": 100.0,
    "A02": 100.0,
    "A03": 85.0
  },
  "scanned_categories": ["A01", "A02", "A03", ...]
}
```

### **Test Specific Branch**

```bash
# Scan develop branch instead of main
python scripts/test_new_url.py https://github.com/example/repo.git \
  --branch develop \
  --framework 1
```

---

## Common Scenarios

### **Scenario 1: Quick Security Check**

You just pushed code and want to know if there are critical security issues:

```bash
python scripts/test_new_url.py https://github.com/yourcompany/yourapp.git
```

- ✅ Defaults to OWASP (most common)
- ✅ Scans main branch (your production code)
- ✅ Takes ~2 minutes
- ✅ Shows security status immediately

### **Scenario 2: Compliance Verification**

Your company needs to verify compliance with specific standards:

```bash
# NIST compliance check
python scripts/test_new_url.py https://github.com/gov-agency/app.git --framework 3

# CIS compliance check
python scripts/test_new_url.py https://github.com/healthcare/hipaa-app.git --framework 2
```

Results show exactly which security categories pass/fail per standard.

### **Scenario 3: Before/After Verification**

Test before and after security improvements:

```bash
# Scan before fixes
python scripts/test_new_url.py https://github.com/example/repo.git \
  --export before_fixes.json

# (Make security improvements...)

# Scan after fixes
python scripts/test_new_url.py https://github.com/example/repo.git \
  --export after_fixes.json

# Compare JSON files to see improvements
```

### **Scenario 4: Feature Branch Security Review**

Review security of a feature before merging:

```bash
python scripts/test_new_url.py https://github.com/example/repo.git \
  --branch feature/new-auth-system \
  --framework 1
```

This shows if the new feature introduces security issues.

---

## Troubleshooting

### **Scan Takes Too Long**

- ⏱️ **Expected**: Large repositories (>10MB) can take 3-5 minutes
- 💡 **Tip**: Check repo size: `git clone --depth 1 && du -sh .`
- ✅ **Solution**: Script has 300-second timeout; Celery workers continue in background

### **Database Connection Error**

```
Error: could not connect to database
```

**Fix:**
1. Ensure PostgreSQL is running
2. Check `.env` file has correct `DATABASE_URL`
3. Run migrations: `python scripts/init_db.py`

### **Scan Not Found**

```
Error: Scan result not found for ID: xxx
```

**Cause:** Celery workers not running (background processing not active)

**Solution:**
- Run direct test instead: `python scripts/direct_test_sast_scan.py`
- Or start Celery worker: `python scripts/start_sast_worker.py`

### **Repository Not Accessible**

```
Error: Failed to clone repository
```

**Causes:**
- URL is incorrect
- Repository is private (need credentials)
- GitHub/GitLab is down

**Fix:** Test URL manually first:
```bash
git clone https://github.com/user/repo.git test_clone
rm -rf test_clone
```

---

## What Gets Checked

### **Bandit Scans For:**
- Hard-coded passwords/secrets
- Insecure crypto functions
- SQL injection vulnerabilities
- Command injection risks
- Insecure deserialization
- Weak password hashing

### **Semgrep Scans For:**
- Authentication bypasses
- Authorization flaws
- Data validation issues
- Injection patterns
- Sensitive data exposure
- Insecure randomness

### **Both Tools Check:**
- Input validation
- Output encoding
- Error handling
- Security headers
- Dependency vulnerabilities

---

## Next Steps After Scanning

### **Priority 1: Critical Issues**
- SQL injection
- Hard-coded secrets
- Authentication bypasses
- Privilege escalation

**Action:** Fix immediately before deployment

### **Priority 2: High Issues**
- Weak cryptography
- Insecure deserialization
- Missing input validation
- Broken access control

**Action:** Fix before next release

### **Priority 3: Medium Issues**
- Missing security headers
- Insufficient logging
- Code quality issues

**Action:** Include in next sprint

### **Priority 4: Low Issues**
- Code patterns
- Best practices
- Documentation

**Action:** Address in future refactoring

---

## Integration with Frontend

The results can be displayed in a web dashboard:

```javascript
// Fetch scan results
const response = await fetch(`/api/v1/scans/${scanId}`);
const results = await response.json();

// Display compliance score
document.getElementById('score').textContent = results.compliance_score + '%';

// Show category breakdown
results.findings_by_category.forEach(category => {
  addCategoryCard(
    category.id,
    category.score,
    category.findings.length
  );
});

// Display remediation guidance
results.findings_by_category.forEach(category => {
  category.findings.forEach(finding => {
    addFindingCard(finding.file, finding.line, finding.remediation);
  });
});
```

---

## Summary

**The Complete Workflow:**

1. ✅ **Submit** → Run script with repo URL
2. ✅ **Scan** → Security scanners analyze code
3. ✅ **Categorize** → Findings mapped to framework
4. ✅ **Score** → Compliance calculated per category
5. ✅ **Report** → Results displayed and exportable
6. ✅ **Fix** → Address findings by priority
7. ✅ **Verify** → Re-scan to confirm improvements

**Total Time:** 2-5 minutes from submission to results

**Frameworks Supported:**
- 🔒 OWASP Top 10 (most comprehensive)
- 🔐 CIS Framework (compliance-focused)
- 📋 NIST 800-53 (government standard)

**Ready to scan? Run:**
```bash
python scripts/test_new_url.py <YOUR_REPO_URL>
```

---

**Questions?** Check `API_REFERENCE.md` for endpoint details.

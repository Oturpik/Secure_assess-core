# API Reference - Framework-Aware Security Scanning

## Overview

This document describes the API endpoints and data structures for the framework-aware security scanning system. These are ready for frontend integration.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

All endpoints require authentication via JWT token in the `Authorization` header:
```
Authorization: Bearer <jwt_token>
```

## Endpoints

### 1. Initiate Scan with Framework Selection

**Endpoint:** `POST /scans/initiate`

**Description:** Start a new security scan using a specific compliance framework.

**Request Body:**
```json
{
  "repository_url": "https://github.com/example/repo.git",
  "branch": "main",
  "framework_id": 1,
  "scan_types": ["sast"],
  "priority": 5
}
```

**Parameters:**
- `repository_url` (string, required): Git repository URL to scan
- `branch` (string, required): Branch name to scan (e.g., "main", "develop")
- `framework_id` (integer, required): Compliance framework ID
  - `1` = OWASP Top 10
  - `2` = CIS Framework  
  - `3` = NIST 800-53
- `scan_types` (array, optional): Types of scans (default: ["sast"])
  - `"sast"` = Static Application Security Testing
  - `"dast"` = Dynamic Application Security Testing
  - `"sca"` = Software Composition Analysis
- `priority` (integer, optional): Scan priority 1-10 (default: 5)

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "framework_id": 1,
  "framework_name": "OWASP",
  "repository_url": "https://github.com/example/repo.git",
  "branch": "main",
  "created_at": "2025-11-18T08:45:00Z"
}
```

### 2. Get Scan Status and Results

**Endpoint:** `GET /scans/{scan_id}`

**Description:** Retrieve the current status and results of a scan.

**Path Parameters:**
- `scan_id` (string, required): The scan ID returned from initiate endpoint

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "complete",
  "framework_id": 1,
  "framework_name": "OWASP",
  "framework_version": "4.0",
  "repository_url": "https://github.com/example/repo.git",
  "branch": "main",
  "scan_date": "2025-11-18T08:45:00Z",
  "compliance_score": 85.5,
  "findings_summary": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8
  },
  "findings_by_category": {
    "A01": {
      "category_name": "Broken Access Control",
      "score": 80,
      "findings": [
        {
          "id": "B303",
          "severity": "critical",
          "message": "Possible insecure hash function used",
          "file": "src/auth/password.py",
          "line": 42,
          "remediation": "Use bcrypt or argon2 instead of MD5"
        }
      ]
    },
    "A02": {
      "category_name": "Cryptographic Failures",
      "score": 90,
      "findings": []
    },
    "A03": {
      "category_name": "Injection",
      "score": 70,
      "findings": [
        {
          "id": "B608",
          "severity": "high",
          "message": "Possible SQL injection vector",
          "file": "src/api/database.py",
          "line": 105,
          "remediation": "Use parameterized queries or ORM"
        }
      ]
    }
  },
  "category_scores": {
    "A01": 80,
    "A02": 90,
    "A03": 70,
    "A04": 100,
    "A05": 85,
    "A06": 95,
    "A07": 75,
    "A08": 85,
    "A09": 90,
    "A10": 100
  },
  "scanned_categories": [
    "A01", "A02", "A03", "A04", "A05", 
    "A06", "A07", "A08", "A09", "A10"
  ]
}
```

### 3. Get Framework Categories

**Endpoint:** `GET /frameworks/{framework_id}/categories`

**Description:** Get all categories defined for a specific compliance framework.

**Path Parameters:**
- `framework_id` (integer, required): Framework ID (1=OWASP, 2=CIS, 3=NIST)

**Response:**
```json
{
  "framework_id": 1,
  "framework_name": "OWASP",
  "framework_version": "4.0",
  "categories": [
    {
      "id": "A01",
      "title": "Broken Access Control",
      "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
      "priority": "High",
      "checks": [
        "Missing authentication",
        "Weak authorization",
        "Privilege escalation",
        "Insecure direct object references"
      ]
    },
    {
      "id": "A02",
      "title": "Cryptographic Failures",
      "description": "Formerly known as Sensitive Data Exposure, this is about failures related to cryptography (or lack thereof).",
      "priority": "High",
      "checks": [
        "Weak cryptographic algorithms",
        "Hard-coded secrets",
        "Insecure randomness",
        "Missing encryption"
      ]
    }
  ]
}
```

### 4. Get Framework Violations (Per Category)

**Endpoint:** `GET /scans/{scan_id}/violations/{framework_id}/{category_id}`

**Description:** Get detailed violation information for a specific framework category.

**Path Parameters:**
- `scan_id` (string, required): The scan ID
- `framework_id` (integer, required): Framework ID
- `category_id` (string, required): Category ID (e.g., "A01")

**Query Parameters:**
- `severity` (string, optional): Filter by severity (critical, high, medium, low)

**Response:**
```json
{
  "category_id": "A03",
  "category_name": "Injection",
  "category_description": "An injection flaws occur when user-supplied input is sent to an interpreter...",
  "compliance_score": 70,
  "total_violations": 3,
  "violations": [
    {
      "id": "B608",
      "type": "SQL Injection",
      "severity": "high",
      "confidence": 0.95,
      "message": "Possible SQL injection vector through string-based query construction",
      "file": "src/api/endpoints.py",
      "line": 105,
      "line_text": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
      "remediation": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [user_id])",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
      ]
    },
    {
      "id": "hardcoded-secret",
      "type": "Hardcoded Secret",
      "severity": "critical",
      "confidence": 1.0,
      "message": "Hardcoded AWS secret key detected",
      "file": "src/config.py",
      "line": 15,
      "line_text": "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'",
      "remediation": "Move secrets to environment variables or secret management service",
      "references": [
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
      ]
    }
  ]
}
```

### 5. List All Scans

**Endpoint:** `GET /scans`

**Description:** Get a paginated list of all scans.

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `limit` (integer, optional): Results per page (default: 10)
- `framework_id` (integer, optional): Filter by framework
- `status` (string, optional): Filter by status (pending, in_progress, complete, failed)
- `sort_by` (string, optional): Sort field (scan_date, compliance_score, repository_url)

**Response:**
```json
{
  "total": 42,
  "page": 1,
  "limit": 10,
  "scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "complete",
      "framework_id": 1,
      "framework_name": "OWASP",
      "repository_url": "https://github.com/example/repo.git",
      "branch": "main",
      "scan_date": "2025-11-18T08:45:00Z",
      "compliance_score": 85.5,
      "findings_count": 27
    }
  ]
}
```

## Data Structures

### Framework Object
```json
{
  "id": 1,
  "name": "OWASP",
  "version": "4.0",
  "description": "OWASP Top 10 2021 - The 10 Most Critical Web Application Security Risks",
  "categories_count": 10
}
```

### Category Object
```json
{
  "id": "A01",
  "title": "Broken Access Control",
  "description": "Access control enforces policy...",
  "priority": "High",
  "checks": ["check1", "check2"],
  "recommendations": ["recommendation1", "recommendation2"]
}
```

### Finding Object
```json
{
  "id": "B303",
  "type": "security_issue",
  "severity": "high",
  "confidence": 0.95,
  "message": "Possible insecure hash function used",
  "file": "src/auth/password.py",
  "line": 42,
  "line_text": "hash = md5(password)",
  "remediation": "Use bcrypt or argon2 instead of MD5"
}
```

## Status Codes

### Scan Status Values
- `pending` - Scan queued, waiting to start
- `in_progress` - Scan currently running
- `complete` - Scan finished successfully
- `failed` - Scan encountered an error

### HTTP Status Codes
- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - User lacks permission
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

## Example Usage

### JavaScript/Frontend
```javascript
// Initiate a scan
const response = await fetch('/api/v1/scans/initiate', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    repository_url: 'https://github.com/example/repo.git',
    branch: 'main',
    framework_id: 1  // OWASP
  })
});

const { scan_id } = await response.json();

// Poll for results
setInterval(async () => {
  const results = await fetch(`/api/v1/scans/${scan_id}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  
  const scan = await results.json();
  
  if (scan.status === 'complete') {
    displayResults(scan);
    clearInterval();
  }
}, 5000);
```

### Display Compliance Breakdown
```javascript
// Show framework categories and scores
const categoryChart = {
  labels: Object.keys(scan.category_scores),
  data: Object.values(scan.category_scores),
  backgroundColor: [
    '#ff6b6b', '#feca57', '#48dbfb', '#ff9ff3', '#54a0ff'
  ]
};

displayRadarChart(categoryChart);

// Show findings per category
scan.findings_by_category.forEach(category => {
  console.log(`${category.id}: ${category.score}%`);
  category.findings.forEach(finding => {
    console.log(`  - ${finding.severity}: ${finding.message}`);
  });
});
```

## Rate Limiting

API requests are rate-limited to:
- 100 requests per minute for authenticated users
- 10 requests per minute for unauthenticated users

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1637234400
```

## Error Handling

All error responses include a standard error object:
```json
{
  "error": {
    "code": "INVALID_FRAMEWORK",
    "message": "Framework with ID 999 not found",
    "details": {
      "framework_id": 999
    }
  }
}
```

## Webhooks (Future)

Webhooks can be configured to receive notifications when scans complete:

```
POST /webhooks/scan-complete
{
  "event": "scan.complete",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "complete",
  "compliance_score": 85.5,
  "timestamp": "2025-11-18T08:45:00Z"
}
```

---

**API Version:** v1  
**Last Updated:** November 18, 2025  
**Status:** Production Ready for Frontend Integration

# Database Setup and Initialization Guide

This guide explains how to set up PostgreSQL locally and initialize the vulnerability databases for the security assessment platform.

## Prerequisites

- Python 3.8+
- PostgreSQL 14+
- pip (Python package manager)

## PostgreSQL Installation (Windows)

1. Download PostgreSQL installer from the official website:
   - Visit https://www.postgresql.org/download/windows/
   - Download the latest version of PostgreSQL

2. Run the installer:
   ```powershell
   # Accept defaults for most options
   # Remember the password you set for the postgres user
   # Port should be 5432 (default)
   ```

3. Verify installation:
   ```powershell
   # Check if PostgreSQL service is running
   Get-Service postgresql*
   
   # Check PostgreSQL version
   psql --version
   ```

4. Create the database:
   ```powershell
   # Login to PostgreSQL as postgres user
   psql -U postgres
   
   # Create database
   CREATE DATABASE security_scanner;
   
   # Create user (replace 'your_password' with a secure password)
   CREATE USER scanner_user WITH PASSWORD 'your_password';
   
   # Grant privileges
   GRANT ALL PRIVILEGES ON DATABASE security_scanner TO scanner_user;
   
   # Exit psql
   \q
   ```

## Environment Setup

1. Create a `.env` file in the project root:
   ```plaintext
   # Database
   DATABASE_URL=postgresql://scanner_user:your_password@localhost:5432/security_scanner
   DB_POOL_SIZE=20
   DB_MAX_OVERFLOW=0
   DB_ECHO=False

   # NVD API (optional)
   NVD_API_KEY=your_nvd_api_key  # Get from https://nvd.nist.gov/developers/request-an-api-key

   # Application
   SECRET_KEY=your_secret_key_at_least_32_chars_long
   ENVIRONMENT=development
   DEBUG=True
   LOG_LEVEL=INFO
   ```

## Initialize Database

1. Install project dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

2. Run database migrations:
   ```powershell
   # Initialize Alembic
   alembic init alembic

   # Create initial tables
   alembic upgrade head
   ```

3. Seed the database:
   ```powershell
   python scripts/seed_vulnerability_data.py
   ```

## Verify Setup

1. Check database tables:
   ```sql
   -- Connect to database
   psql -U scanner_user -d security_scanner

   -- List tables
   \dt

   -- Check frameworks
   SELECT * FROM frameworks;

   -- Check recent vulnerabilities
   SELECT cve_id, title, severity, cvss_score 
   FROM vulnerabilities 
   ORDER BY published_date DESC 
   LIMIT 5;
   ```

## Automated Database Updates

To keep the vulnerability database up-to-date, you can set up a scheduled task:

1. Create a PowerShell script `update_vulnerabilities.ps1`:
   ```powershell
   # Activate virtual environment if using one
   # .\venv\Scripts\Activate

   # Run the seeding script
   python scripts\seed_vulnerability_data.py
   ```

2. Create a scheduled task:
   ```powershell
   # Create daily task at 2 AM
   $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\path\to\update_vulnerabilities.ps1"
   $Trigger = New-ScheduledTaskTrigger -Daily -At 2am
   Register-ScheduledTask -TaskName "Update Vulnerability Database" -Action $Action -Trigger $Trigger
   ```

## Troubleshooting

1. Database connection issues:
   - Verify PostgreSQL service is running
   - Check connection string in `.env`
   - Ensure firewall allows connections to port 5432
   - Verify user permissions

2. Seeding issues:
   - Check NVD API key if provided
   - Review logs for specific error messages
   - Ensure internet connectivity for CVE data fetching

3. Migration issues:
   - Remove all tables and run `alembic upgrade head` again
   - Check alembic version history: `alembic history`
   - Review migration logs in `alembic/versions/`
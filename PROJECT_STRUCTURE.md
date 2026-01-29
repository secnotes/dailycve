# CVE Daily - Project Structure

This project automatically collects, filters, and reports on high-risk CVEs daily.

## Directory Structure

```
cvedaily/
├── src/                          # Source code
│   ├── __init__.py              # Package initialization
│   ├── collector.py             # Main CVE collection logic
│   ├── reporter.py              # Report generation logic
│   └── config.py                # Configuration settings
├── reports/                     # Archived reports (created at runtime)
│   └── [year]/                  # Yearly subdirectories
│       └── daily_cve_[date].md  # Daily markdown reports
├── .github/
│   └── workflows/
│       └── daily-update.yml     # GitHub Actions workflow
├── test_collector.py            # Test script for verification
├── requirements.txt             # Python dependencies
├── .env.example                 # Example environment file
├── README.md                   # Project documentation
└── report.html                 # Daily HTML report (generated)
```

## Components

### 1. Collector (`src/collector.py`)
- Fetches CVE data from NVD, GitHub advisories
- Loads CISA KEV and EPSS datasets
- Filters vulnerabilities based on risk criteria
- Optionally enhances descriptions using AI

### 2. Reporter (`src/reporter.py`)
- Generates HTML reports with styling
- Creates markdown archives for historical records
- Formats vulnerability data for readability

### 3. Configuration (`src/config.py`)
- Centralized configuration management
- Risk thresholds (CVSS > 7.0, EPSS > 0.10)
- API endpoints and parameters
- Output paths and settings

### 4. GitHub Actions Workflow
- Automates daily execution at 00:00 UTC
- Commits updated reports to repository
- Runs the collection process on schedule

## Installation & Usage

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Optional: Add your OpenAI API key to `.env` for AI-enhanced descriptions
4. Run manually: `python src/main.py`
5. The system creates daily reports automatically when deployed to GitHub

## Risk Classification Criteria

High-risk vulnerabilities are identified by meeting ANY of these criteria:
- CVSS score > 7.0 (High or Critical severity)
- Listed in CISA KEV (Known Exploited Vulnerabilities catalog)
- EPSS score > 0.10 (higher probability of exploitation)

## Reports

- **HTML Report** (`report.html`): Daily dashboard-style view
- **Markdown Archives** (`reports/[year]/daily_cve_[date].md`): Historical records by year
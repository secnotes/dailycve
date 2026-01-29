# CVE Daily

Automated daily CVE monitoring system that aggregates high-risk vulnerabilities from multiple public sources and generates human-readable reports.

## 🚀 Features

- **Multi-source Collection**: Fetches latest CVEs from NVD, GitHub advisories, CISA KEV, and EPSS
- **Intelligent Filtering**: Identifies high-risk vulnerabilities based on:
  - CVSS score > 7.0 (High/Critical severity)
  - Presence in CISA KEV (Known Exploited Vulnerabilities) List
  - EPSS score > 0.10 (Exploitation probability)
- **AI Enhancement**: Uses OpenAI to improve vulnerability descriptions for readability (optional)
- **Interactive Reports**: Generates rich HTML reports with filtering capabilities
- **Historical Archiving**: Stores daily reports in Markdown format organized by year
- **Automated Updates**: Scheduled execution via GitHub Actions

## 📁 Project Structure

```
dailycve/
├── src/                           # Source code
│   ├── __init__.py               # Package initialization
│   ├── collector.py              # Main CVE collection logic
│   ├── reporter.py               # Report generation logic
│   └── config.py                 # Configuration settings
├── reports/                      # Archived reports (runtime generated)
│   └── [year]/                   # Yearly subdirectories
│       └── daily_cve_[date].md   # Daily markdown reports
├── .github/
│   └── workflows/
│       └── daily-update.yml      # GitHub Actions workflow
├── test_collector.py             # Test script for verification
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment configuration example
└── report.html                   # Daily HTML report (runtime generated)
```

## ⚙️ Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/secnotes/dailycve.git
   cd dailycve
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment (optional)**:
   ```bash
   cp .env.example .env
   # Add your OpenAI API key to .env if you want AI-enhanced descriptions
   ```

4. **Run locally**:
   ```bash
   python src/main.py
   ```

## 🛠️ Configuration

The system uses several configuration parameters located in `src/config.py`:

- `CVSS_THRESHOLD`: Minimum CVSS score to consider a vulnerability high-risk (default: 7.0)
- `EPSS_THRESHOLD`: Minimum EPSS score for high-risk classification (default: 0.10)
- `LOOKBACK_DAYS`: Number of days to look back for new CVEs (default: 1)

## 📊 Risk Classification Criteria

High-risk vulnerabilities are identified by meeting ANY of these criteria:
- CVSS score > 7.0 (High or Critical severity)
- Listed in CISA KEV (Known Exploited Vulnerabilities catalog)
- EPSS score > 0.10 (higher probability of exploitation)

## 🔧 Customization

You can customize the system behavior by modifying `src/config.py`:
- Adjust risk thresholds
- Change report output paths
- Modify data source URLs
- Enable/disable AI enhancement

## 🤖 AI Enhancement

The system supports AI-enhanced vulnerability descriptions using OpenAI. To enable:
1. Add your `OPENAI_API_KEY` to the `.env` file
2. The system will automatically enhance descriptions for better readability

## 📈 Output Files

After execution, the system generates:
- `report.html`: Interactive dashboard-style report with filtering capabilities
- `reports/[year]/daily_cve_[date].md`: Markdown archive of daily findings

## 🏗️ Architecture

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
- Risk thresholds and API endpoints
- Output paths and settings

## 📄 License

MIT
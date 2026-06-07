import os
from datetime import datetime

# Configuration for CVE Daily
class Config:
    # Data sources
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # CISA KEV URL
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # EPSS data URL (will use date formatting)
    EPSS_BASE_URL = "https://epss.cyentia.com/"

    # GitHub advisories feed
    GITHUB_ADVISORIES_URL = "https://github.com/advisories.atom"

    # Thresholds for high-risk classification
    CVSS_THRESHOLD = 7.0  # Consider vulnerabilities with CVSS score higher than this as high-risk
    EPSS_THRESHOLD = 0.01  # Consider vulnerabilities with EPSS score higher than or equal to this as high-risk

    # Number of days to look back for new CVEs
    LOOKBACK_DAYS = 1

    # Output settings
    REPORT_HTML_PATH = "docs/index.html"
    REPORT_DIR = f"docs/reports/{datetime.now().year}"

    # AI Curation settings (requires AI_API_KEY in environment)
    AI_CURATION_ENABLED = os.getenv('AI_API_KEY') is not None
    AI_CURATED_CACHE_PATH = "docs/ai_curated.json"

    # CVE-specific AI categories
    AI_CVE_CATEGORIES = [
        "桌面操作系统",
        "移动安全",
        "IoT安全",
        "云安全",
        "网络设备",
        "工业控制",
        "Web安全",
        "数据库与中间件",
        "其他",
    ]

    # Category icon mapping for HTML display
    AI_CATEGORY_ICONS = {
        "桌面操作系统": "💻",
        "移动安全": "📱",
        "IoT安全": "📡",
        "云安全": "☁️",
        "网络设备": "🌐",
        "工业控制": "🏭",
        "Web安全": "🔐",
        "数据库与中间件": "🗄️",
        "其他": "📌",
    }

    @staticmethod
    def get_current_year_report_dir():
        """Get the report directory for the current year"""
        return f"docs/reports/{datetime.now().year}"
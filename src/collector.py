import os
import json
import requests
import xml.etree.ElementTree as ET
import pandas as pd
from datetime import datetime, timedelta
import html2text
from openai import OpenAI
from dotenv import load_dotenv
from html import unescape

# Load environment variables
load_dotenv()

from config import Config

class CVECollector:
    def __init__(self):
        self.cisa_kev_list = []
        self.epss_data = {}
        self.openai_client = None

        # Initialize OpenAI client if API key is available
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if openai_api_key:
            self.openai_client = OpenAI(api_key=openai_api_key)

        # Load CISA KEV data
        self.load_cisa_kev()
        # Load EPSS data
        self.load_epss_data()

        # Enable AI enhancement based on config
        self.enable_ai = Config.ENABLE_AI_ENHANCEMENT

    def load_cisa_kev(self):
        """Load CISA Known Exploited Vulnerabilities list"""
        try:
            response = requests.get(Config.CISA_KEV_URL)
            if response.status_code == 200:
                data = response.json()
                # Extract CVE IDs from the list
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        self.cisa_kev_list.append(cve_id)
        except Exception as e:
            print(f"Error loading CISA KEV: {e}")

    def load_epss_data(self):
        """Load EPSS scores from public source"""
        try:
            # Get yesterday's date for EPSS data (as today's might not be available yet)
            yesterday = datetime.now() - timedelta(days=1)
            date_str = yesterday.strftime("%Y-%m-%d")

            url = f"{Config.EPSS_BASE_URL}epss_scores-{date_str}.csv.gz"
            response = requests.get(url)

            if response.status_code != 200:
                # Try alternative date format (without gzip)
                url = f"{Config.EPSS_BASE_URL}epss_scores-{date_str}.csv"
                response = requests.get(url)

            if response.status_code == 200:
                # Parse CSV content
                lines = response.text.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        cve_id = parts[0].strip()
                        epss_score = float(parts[1].strip())
                        self.epss_data[cve_id] = epss_score
        except Exception as e:
            print(f"Error loading EPSS data: {e}")

    def get_nvd_cves(self, days=1):
        """Fetch latest CVEs from NVD"""
        cves = []
        try:
            # Calculate date range
            start_date = datetime.now() - timedelta(days=days)
            end_date = datetime.now()

            start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S")
            end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S")

            # Use NVD API (without API key, limited to basic data)
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

            # First, fetch vulnerabilities published in the date range
            pub_params = {
                "pubStartDate": start_str,
                "pubEndDate": end_str,
                "resultsPerPage": 2000  # Maximum allowed
            }

            response = requests.get(base_url, params=pub_params)
            if response.status_code == 200:
                data = response.json()

                for item in data.get('vulnerabilities', []):
                    cve_item = item.get('cve', {})
                    cve_id = cve_item.get('id', '')

                    # Extract CVSS metrics
                    cvss_score = 0
                    metrics = cve_item.get('metrics', {})

                    # Look for CVSS v3.x scores
                    cvss_metrics = metrics.get('cvssMetricV31', []) or \
                                  metrics.get('cvssMetricV30', [])

                    if cvss_metrics:
                        cvss_data = cvss_metrics[0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0)

                    # Look for CVSS v2 scores if v3 is not available
                    if cvss_score == 0:
                        cvss2_metrics = metrics.get('cvssMetricV2', [])
                        if cvss2_metrics:
                            cvss_data = cvss2_metrics[0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore', 0)

                    # Extract description
                    descriptions = cve_item.get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break

                    # Extract vendor and product information from configurations (if available)
                    vendors = set()
                    products = set()

                    configurations = cve_item.get('configurations', [])
                    for config in configurations:
                        nodes = config.get('nodes', [])
                        for node in nodes:
                            # Process both children and cpeMatch at this level
                            # Get children nodes recursively
                            child_nodes = node.get('children', [])
                            all_nodes = [node]  # Start with the current node

                            # Add children to the list to process them too
                            all_nodes.extend(child_nodes)

                            for sub_node in all_nodes:
                                # Get cpe matches from this sub_node
                                cpe_match_list = sub_node.get('cpeMatch', [])
                                for cpe in cpe_match_list:
                                    if cpe.get('vulnerable', False):
                                        cpe_uri = cpe.get('criteria', '')
                                        if cpe_uri:
                                            # Parse CPE URI to extract vendor and product
                                            # Format: cpe:2.3:o:vendor:product:version
                                            parts = cpe_uri.split(':')
                                            if len(parts) >= 6:  # Ensure we have enough parts
                                                vendor = parts[3] if parts[3] != '*' else ''
                                                product = parts[4] if parts[4] != '*' else ''

                                                if vendor and vendor != '-':
                                                    vendors.add(vendor.lower())
                                                if product and product != '-':
                                                    products.add(product.lower())

                    # If no vendor info found from configurations, try to extract from description
                    if not vendors and not products:
                        # Look for common vendor names in the description and title
                        text_to_search = f"{cve_id} {description}".lower()

                        common_vendors = [
                            'microsoft', 'apple', 'google', 'adobe', 'oracle', 'ibm', 'cisco',
                            'hp', 'dell', 'intel', 'amd', 'nvidia', 'samsung', 'huawei', 'xiaomi',
                            'linux', 'ubuntu', 'debian', 'red hat', 'centos', 'fedora', 'opensuse',
                            'apache', 'nginx', 'microsoft', 'mssql', 'mysql', 'postgresql',
                            'vmware', 'citrix', 'juniper', 'fortinet', 'checkpoint', 'symantec',
                            'trendmicro', 'mcafee', 'avast', 'avg', 'bitdefender', 'kaspersky',
                            'android', 'ios', 'windows', 'macos', 'linux', 'firefox', 'chrome',
                            'safari', 'edge', 'wordpress', 'drupal', 'magento', 'prestashop',
                            'joomla', 'shopify', 'woocommerce', 'paypal', 'stripe', 'zendesk',
                            'salesforce', 'sap', 'oracle', 'ibm', 'atlassian', 'jenkins',
                            'docker', 'kubernetes', 'aws', 'azure', 'gcp', 'oracle cloud',
                            'microsoft', 'facebook', 'meta', 'instagram', 'whatsapp', 'twitter',
                            'linkedin', 'youtube', 'tiktok', 'snapchat', 'telegram', 'slack',
                            'zoom', 'teams', 'skype', 'cisco', 'webex', 'polycom', 'avaya',
                            'microsoft', 'exchange', 'outlook', 'onedrive', 'sharepoint'
                        ]

                        # Search for vendors in the combined text
                        for vendor in common_vendors:
                            if vendor in text_to_search:
                                vendors.add(vendor)

                    # Check if it's high risk
                    is_high_risk = (
                        cvss_score > Config.CVSS_THRESHOLD or
                        cve_id in self.cisa_kev_list or
                        (cve_id in self.epss_data and self.epss_data[cve_id] > Config.EPSS_THRESHOLD)
                    )

                    if is_high_risk:
                        cves.append({
                            'id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'epss_score': self.epss_data.get(cve_id, 0),
                            'in_cisa_kev': cve_id in self.cisa_kev_list,
                            'vendors': list(vendors),
                            'products': list(products),
                            'published_date': cve_item.get('published', ''),
                            'last_modified': cve_item.get('lastModified', ''),
                            'entry_type': 'published'  # Mark as published
                        })

            # Next, fetch vulnerabilities that were modified in the date range
            # This captures CVEs that were updated/corrected recently
            mod_params = {
                "lastModStartDate": start_str,
                "lastModEndDate": end_str,
                "resultsPerPage": 2000  # Maximum allowed
            }

            response_mod = requests.get(base_url, params=mod_params)
            if response_mod.status_code == 200:
                data_mod = response_mod.json()

                for item in data_mod.get('vulnerabilities', []):
                    cve_item = item.get('cve', {})
                    cve_id = cve_item.get('id', '')

                    # Check if this CVE is already in our list (to avoid duplicates)
                    if any(cve['id'] == cve_id for cve in cves):
                        continue  # Skip if already present

                    # Extract CVSS metrics
                    cvss_score = 0
                    metrics = cve_item.get('metrics', {})

                    # Look for CVSS v3.x scores
                    cvss_metrics = metrics.get('cvssMetricV31', []) or \
                                  metrics.get('cvssMetricV30', [])

                    if cvss_metrics:
                        cvss_data = cvss_metrics[0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0)

                    # Look for CVSS v2 scores if v3 is not available
                    if cvss_score == 0:
                        cvss2_metrics = metrics.get('cvssMetricV2', [])
                        if cvss2_metrics:
                            cvss_data = cvss2_metrics[0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore', 0)

                    # Extract description
                    descriptions = cve_item.get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break

                    # Extract vendor and product information from configurations (if available)
                    vendors = set()
                    products = set()

                    configurations = cve_item.get('configurations', [])
                    for config in configurations:
                        nodes = config.get('nodes', [])
                        for node in nodes:
                            # Process both children and cpeMatch at this level
                            # Get children nodes recursively
                            child_nodes = node.get('children', [])
                            all_nodes = [node]  # Start with the current node

                            # Add children to the list to process them too
                            all_nodes.extend(child_nodes)

                            for sub_node in all_nodes:
                                # Get cpe matches from this sub_node
                                cpe_match_list = sub_node.get('cpeMatch', [])
                                for cpe in cpe_match_list:
                                    if cpe.get('vulnerable', False):
                                        cpe_uri = cpe.get('criteria', '')
                                        if cpe_uri:
                                            # Parse CPE URI to extract vendor and product
                                            # Format: cpe:2.3:o:vendor:product:version
                                            parts = cpe_uri.split(':')
                                            if len(parts) >= 6:  # Ensure we have enough parts
                                                vendor = parts[3] if parts[3] != '*' else ''
                                                product = parts[4] if parts[4] != '*' else ''

                                                if vendor and vendor != '-':
                                                    vendors.add(vendor.lower())
                                                if product and product != '-':
                                                    products.add(product.lower())

                    # If no vendor info found from configurations, try to extract from description
                    if not vendors and not products:
                        # Look for common vendor names in the description and title
                        text_to_search = f"{cve_id} {description}".lower()

                        common_vendors = [
                            'microsoft', 'apple', 'google', 'adobe', 'oracle', 'ibm', 'cisco',
                            'hp', 'dell', 'intel', 'amd', 'nvidia', 'samsung', 'huawei', 'xiaomi',
                            'linux', 'ubuntu', 'debian', 'red hat', 'centos', 'fedora', 'opensuse',
                            'apache', 'nginx', 'microsoft', 'mssql', 'mysql', 'postgresql',
                            'vmware', 'citrix', 'juniper', 'fortinet', 'checkpoint', 'symantec',
                            'trendmicro', 'mcafee', 'avast', 'avg', 'bitdefender', 'kaspersky',
                            'android', 'ios', 'windows', 'macos', 'linux', 'firefox', 'chrome',
                            'safari', 'edge', 'wordpress', 'drupal', 'magento', 'prestashop',
                            'joomla', 'shopify', 'woocommerce', 'paypal', 'stripe', 'zendesk',
                            'salesforce', 'sap', 'oracle', 'ibm', 'atlassian', 'jenkins',
                            'docker', 'kubernetes', 'aws', 'azure', 'gcp', 'oracle cloud',
                            'microsoft', 'facebook', 'meta', 'instagram', 'whatsapp', 'twitter',
                            'linkedin', 'youtube', 'tiktok', 'snapchat', 'telegram', 'slack',
                            'zoom', 'teams', 'skype', 'cisco', 'webex', 'polycom', 'avaya',
                            'microsoft', 'exchange', 'outlook', 'onedrive', 'sharepoint'
                        ]

                        # Search for vendors in the combined text
                        for vendor in common_vendors:
                            if vendor in text_to_search:
                                vendors.add(vendor)

                    # Check if it's high risk (using the original CVSS, CISA KEV, EPSS scores)
                    is_high_risk = (
                        cvss_score > Config.CVSS_THRESHOLD or
                        cve_id in self.cisa_kev_list or
                        (cve_id in self.epss_data and self.epss_data[cve_id] > Config.EPSS_THRESHOLD)
                    )

                    if is_high_risk:
                        cves.append({
                            'id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'epss_score': self.epss_data.get(cve_id, 0),
                            'in_cisa_kev': cve_id in self.cisa_kev_list,
                            'vendors': list(vendors),
                            'products': list(products),
                            'published_date': cve_item.get('published', ''),
                            'last_modified': cve_item.get('lastModified', ''),
                            'entry_type': 'modified'  # Mark this as a modified entry
                        })
        except Exception as e:
            print(f"Error fetching NVD CVEs: {e}")

        return cves

    def get_github_advisories(self, days=1):
        """Fetch security advisories from GitHub"""
        cves = []
        try:
            # GitHub Security Advisories RSS feed
            url = "https://github.com/advisories.atom"
            response = requests.get(url)

            if response.status_code == 200:
                # Parse the XML content
                root = ET.fromstring(response.content)

                # Calculate date threshold
                date_threshold = datetime.now() - timedelta(days=days)

                # Find all entries in the feed
                for entry in root.findall('.//{http://www.w3.org/2005/Atom}entry'):
                    # Get entry title and link
                    title_elem = entry.find('{http://www.w3.org/2005/Atom}title')
                    title = title_elem.text if title_elem is not None else ""

                    published_elem = entry.find('{http://www.w3.org/2005/Atom}published')
                    if published_elem is not None:
                        # Parse published date
                        published_str = published_elem.text
                        # Handle ISO format date
                        published = datetime.fromisoformat(published_str.replace('Z', '+00:00').split('+')[0])
                    else:
                        continue

                    if published.date() >= date_threshold.date():
                        # Look for CVE in title
                        import re
                        cve_match = re.search(r'CVE-\d{4}-\d+', title, re.IGNORECASE)
                        if cve_match:
                            cve_id = cve_match.group().upper()

                            # Get summary/description
                            summary_elem = entry.find('{http://www.w3.org/2005/Atom}summary')
                            description = summary_elem.text if summary_elem is not None else ""

                            # Try to extract vendors and products from title or summary
                            vendors = set()
                            products = set()

                            # Look for common vendor names in the title
                            title_lower = title.lower()
                            common_vendors = ['android', 'apple', 'microsoft', 'linux', 'adobe', 'oracle', 'ibm', 'google', 'facebook', 'twitter', 'amazon', 'cisco', 'juniper', 'hp', 'dell', 'intel', 'amd', 'nvidia', 'vmware', 'red hat', 'apache', 'magento', 'drupal', 'wordpress', 'jquery', 'nginx', 'mssql', 'mysql', 'postgresql']

                            for vendor in common_vendors:
                                if vendor in title_lower:
                                    vendors.add(vendor)

                            # For GitHub advisories, we'll assume high severity based on publication
                            cves.append({
                                'id': cve_id,
                                'description': description,
                                'cvss_score': 0,  # Unknown from GitHub feed
                                'epss_score': self.epss_data.get(cve_id, 0),
                                'in_cisa_kev': cve_id in self.cisa_kev_list,
                                'vendors': list(vendors),
                                'products': [],  # Not available from GitHub feed
                                'published_date': published.isoformat(),
                                'last_modified': '',
                                'source': 'GitHub'
                            })
        except Exception as e:
            print(f"Error fetching GitHub advisories: {e}")

        return cves

    def enhance_description_with_ai(self, cve_id, description):
        """Enhance CVE description using AI for better readability"""
        if not self.openai_client or not self.enable_ai:
            return description

        try:
            prompt = f"""Please enhance and summarize this CVE description to make it more readable and understandable for security professionals. Make it concise but informative, highlighting the key vulnerability characteristics and potential impact:

CVE: {cve_id}

Description: {description}

Provide a clear, professional summary."""

            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert who summarizes vulnerability information clearly and concisely."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.3
            )

            enhanced_desc = response.choices[0].message.content.strip()
            return enhanced_desc
        except Exception as e:
            print(f"Error enhancing description with AI: {e}")
            return description

    def collect_daily_cves(self, days=Config.LOOKBACK_DAYS):
        """Collect CVEs from all sources"""
        print(f"Collecting CVEs from the last {days} day(s)...")

        # Get CVEs from NVD
        nvd_cves = self.get_nvd_cves(days)
        print(f"Found {len(nvd_cves)} high-risk CVEs from NVD (published and modified)")

        # Get advisories from GitHub
        github_advisories = self.get_github_advisories(days)
        print(f"Found {len(github_advisories)} advisories from GitHub")

        # Combine and deduplicate
        all_cves = {}

        for cve in nvd_cves + github_advisories:
            cve_id = cve['id']
            if cve_id not in all_cves:
                # Enhance description with AI
                cve['description'] = self.enhance_description_with_ai(cve_id, cve['description'])
                all_cves[cve_id] = cve

        # Convert to list and sort by the most recent date (either published or last modified)
        result = list(all_cves.values())

        # Sort by the more recent of published_date or last_modified date
        def get_sort_date(cve):
            pub_date_str = cve.get('published_date', '')
            mod_date_str = cve.get('last_modified', '')

            # Convert date strings to datetime objects for comparison
            pub_date = datetime.min
            mod_date = datetime.min

            if pub_date_str:
                try:
                    pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00').split('+')[0])
                except ValueError:
                    pass

            if mod_date_str:
                try:
                    mod_date = datetime.fromisoformat(mod_date_str.replace('Z', '+00:00').split('+')[0])
                except ValueError:
                    pass

            # Return the later of the two dates
            return max(pub_date, mod_date)

        result.sort(key=get_sort_date, reverse=True)

        print(f"Total high-risk CVEs collected: {len(result)}")
        return result
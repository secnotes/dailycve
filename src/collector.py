import os
import json
import requests
import xml.etree.ElementTree as ET
import pandas as pd
import zipfile
import io
from datetime import datetime, timedelta
import html2text
from openai import OpenAI
from dotenv import load_dotenv
from html import unescape
import re

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

    def get_cvelistv5_cves(self, days=1):
        """Fetch CVEs from CVEProject/cvelistV5"""
        cves = []
        try:
            # Calculate the date for which we need to download the delta
            target_date = datetime.now() - timedelta(days=days)
            date_str = target_date.strftime("%Y-%m-%d")

            print(f"Attempting to download CVEs for date: {date_str}")

            # Construct the URL for the delta ZIP file
            zip_url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{date_str}_at_end_of_day/{date_str}_delta_CVEs_at_end_of_day.zip"

            print(f"Downloading from: {zip_url}")

            # Try downloading with the proxy if direct download fails
            try:
                response = requests.get(zip_url, timeout=60)
            except:
                print("Direct download failed, trying with proxy...")
                proxies = {
                    'http': 'http://192.168.17.1:7890',
                    'https': 'https://192.168.17.1:7890'
                }
                try:
                    response = requests.get(zip_url, timeout=60, proxies=proxies)
                except:
                    print("Proxy download failed as well.")
                    return []

            if response.status_code == 200:
                print(f"Successfully downloaded the ZIP file for {date_str}")

                # Create the directory to store the downloaded ZIP
                zip_dir = f"docs/json/{target_date.year}/{target_date.month:02d}"
                os.makedirs(zip_dir, exist_ok=True)

                # Save the ZIP file to the directory
                zip_filename = os.path.join(zip_dir, f"{date_str}_delta_CVEs_at_end_of_day.zip")
                with open(zip_filename, 'wb') as f:
                    f.write(response.content)
                print(f"Saved ZIP file to: {zip_filename}")

                # Extract the ZIP file in memory
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                    print(f"Extracting {len(zip_file.namelist())} files from the ZIP...")

                    for file_info in zip_file.filelist:
                        if file_info.filename.endswith('.json'):
                            # Read the JSON file
                            with zip_file.open(file_info.filename) as json_file:
                                try:
                                    cve_data = json.loads(json_file.read().decode('utf-8'))

                                    # Process the CVE data according to the v5 schema
                                    cve_id = cve_data.get('cveMetadata', {}).get('cveId', '')
                                    if cve_id:
                                        # Extract description
                                        description = ""
                                        descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
                                        for desc in descriptions:
                                            if desc.get('lang') == 'en':
                                                description = desc.get('value', '')
                                                break

                                        # Extract CVSS metrics
                                        cvss_score = 0
                                        metrics = cve_data.get('containers', {}).get('cna', {}).get('metrics', [])
                                        for metric_group in metrics:
                                            # Check for CVSS v4.x
                                            if 'cvssV4_0' in metric_group:
                                                cvss_data = metric_group['cvssV4_0']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            # Check for CVSS v3.x
                                            elif 'cvssV3_1' in metric_group:
                                                cvss_data = metric_group['cvssV3_1']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            elif 'cvssV3_0' in metric_group:
                                                cvss_data = metric_group['cvssV3_0']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            # Check for CVSS v2
                                            elif 'cvssV2_0' in metric_group:
                                                cvss_data = metric_group['cvssV2_0']
                                                cvss_score = cvss_data.get('baseScore', 0)

                                        # Extract vendor and product information from affected
                                        vendors = set()
                                        products = set()

                                        affected_list = cve_data.get('containers', {}).get('cna', {}).get('affected', [])
                                        for affected in affected_list:
                                            vendor = affected.get('vendor', '')
                                            product = affected.get('product', '')

                                            if vendor and vendor.lower() not in ['-', '*', '']:
                                                vendors.add(vendor.lower())
                                            if product and product.lower() not in ['-', '*', '']:
                                                products.add(product.lower())

                                            # Also check for platforms, modules, etc.
                                            platforms = affected.get('platforms', [])
                                            for platform in platforms:
                                                if platform and platform.lower() not in ['-', '*', '']:
                                                    vendors.add(platform.lower())

                                            # Process versions to extract more vendor/product info
                                            versions = affected.get('versions', [])
                                            for version in versions:
                                                if 'changes' in version:
                                                    for change in version['changes']:
                                                        value = change.get('value', '')
                                                        if value and value.lower() not in ['-', '*', '']:
                                                            vendors.add(value.lower())

                                        # Extract publication date
                                        published_date = cve_data.get('cveMetadata', {}).get('datePublished', '')
                                        last_modified = cve_data.get('cveMetadata', {}).get('dateUpdated', '')

                                        # Determine entry type based on dates
                                        target_date_str = target_date.strftime("%Y-%m-%d")
                                        entry_type = 'published'  # Default assumption

                                        # If published date matches target date, it's newly published
                                        if published_date and published_date.startswith(target_date_str):
                                            entry_type = 'published'
                                        # If published earlier but modified on target date, it's modified
                                        elif (published_date and not published_date.startswith(target_date_str) and
                                              last_modified and last_modified.startswith(target_date_str)):
                                            entry_type = 'modified'
                                        # If no published date but has modification on target date, consider as modified
                                        elif (not published_date and last_modified and
                                              last_modified.startswith(target_date_str)):
                                            entry_type = 'modified'
                                        # Otherwise, treat as published if it has data for the target date
                                        else:
                                            entry_type = 'published'

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
                                                'products': list(products),  # Keep products for processing but we'll not use them in the UI
                                                'published_date': published_date,
                                                'last_modified': last_modified,
                                                'entry_type': entry_type
                                            })

                                except json.JSONDecodeError:
                                    print(f"Could not decode JSON for file: {file_info.filename}")
                                    continue
                                except Exception as e:
                                    print(f"Error processing {file_info.filename}: {str(e)}")
                                    continue

                print(f"Processed {len(cves)} high-risk CVEs from {date_str} delta")
            else:
                print(f"Failed to download CVEs for {date_str}. Status code: {response.status_code}")

                # If the requested date is in the future, try the previous day
                if target_date > datetime.now().replace(hour=0, minute=0, second=0, microsecond=0):
                    print("Requested date is in the future. Trying with one day earlier...")
                    yesterday_target = target_date - timedelta(days=1)
                    yesterday_date_str = yesterday_target.strftime("%Y-%m-%d")

                    yesterday_zip_url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{yesterday_date_str}_at_end_of_day/{yesterday_date_str}_delta_CVEs_at_end_of_day.zip"

                    print(f"Trying alternative URL: {yesterday_zip_url}")
                    try:
                        response = requests.get(yesterday_zip_url, timeout=60)
                    except:
                        print("Alternative download failed, trying with proxy...")
                        proxies = {
                            'http': 'http://192.168.17.1:7890',
                            'https': 'https://192.168.17.1:7890'
                        }
                        try:
                            response = requests.get(yesterday_zip_url, timeout=60, proxies=proxies)
                        except:
                            print("Alternative proxy download failed as well.")
                            return []

                    if response.status_code == 200:
                        print(f"Successfully downloaded the ZIP file for {yesterday_date_str}")

                        # Create the directory to store the downloaded ZIP
                        zip_dir = f"docs/json/{yesterday_target.year}/{yesterday_target.month:02d}"
                        os.makedirs(zip_dir, exist_ok=True)

                        # Save the ZIP file to the directory
                        zip_filename = os.path.join(zip_dir, f"{yesterday_date_str}_delta_CVEs_at_end_of_day.zip")
                        with open(zip_filename, 'wb') as f:
                            f.write(response.content)
                        print(f"Saved ZIP file to: {zip_filename}")

                        # Extract the ZIP file in memory
                        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                            print(f"Extracting {len(zip_file.namelist())} files from the ZIP...")

                            for file_info in zip_file.filelist:
                                if file_info.filename.endswith('.json'):
                                    # Read the JSON file
                                    with zip_file.open(file_info.filename) as json_file:
                                        try:
                                            cve_data = json.loads(json_file.read().decode('utf-8'))

                                            # Process the CVE data according to the v5 schema
                                            cve_id = cve_data.get('cveMetadata', {}).get('cveId', '')
                                            if cve_id:
                                                # Extract description
                                                description = ""
                                                descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
                                                for desc in descriptions:
                                                    if desc.get('lang') == 'en':
                                                        description = desc.get('value', '')
                                                        break

                                                # Extract CVSS metrics
                                                cvss_score = 0
                                                metrics = cve_data.get('containers', {}).get('cna', {}).get('metrics', [])
                                                for metric_group in metrics:
                                                    # Check for CVSS v4.x
                                                    if 'cvssV4_0' in metric_group:
                                                        cvss_data = metric_group['cvssV4_0']
                                                        cvss_score = cvss_data.get('baseScore', 0)
                                                    # Check for CVSS v3.x
                                                    elif 'cvssV3_1' in metric_group:
                                                        cvss_data = metric_group['cvssV3_1']
                                                        cvss_score = cvss_data.get('baseScore', 0)
                                                    elif 'cvssV3_0' in metric_group:
                                                        cvss_data = metric_group['cvssV3_0']
                                                        cvss_score = cvss_data.get('baseScore', 0)
                                                    # Check for CVSS v2
                                                    elif 'cvssV2_0' in metric_group:
                                                        cvss_data = metric_group['cvssV2_0']
                                                        cvss_score = cvss_data.get('baseScore', 0)

                                                # Extract vendor and product information from affected
                                                vendors = set()
                                                products = set()

                                                affected_list = cve_data.get('containers', {}).get('cna', {}).get('affected', [])
                                                for affected in affected_list:
                                                    vendor = affected.get('vendor', '')
                                                    product = affected.get('product', '')

                                                    if vendor and vendor.lower() not in ['-', '*', '']:
                                                        vendors.add(vendor.lower())
                                                    if product and product.lower() not in ['-', '*', '']:
                                                        products.add(product.lower())

                                                    # Also check for platforms, modules, etc.
                                                    platforms = affected.get('platforms', [])
                                                    for platform in platforms:
                                                        if platform and platform.lower() not in ['-', '*', '']:
                                                            vendors.add(platform.lower())

                                                    # Process versions to extract more vendor/product info
                                                    versions = affected.get('versions', [])
                                                    for version in versions:
                                                        if 'changes' in version:
                                                            for change in version['changes']:
                                                                value = change.get('value', '')
                                                                if value and value.lower() not in ['-', '*', '']:
                                                                    vendors.add(value.lower())

                                                # Extract publication date
                                                published_date = cve_data.get('cveMetadata', {}).get('datePublished', '')
                                                last_modified = cve_data.get('cveMetadata', {}).get('dateUpdated', '')

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
                                                        'products': list(products),  # Keep products for processing but we'll not use them in the UI
                                                        'published_date': published_date,
                                                        'last_modified': last_modified,
                                                        'entry_type': 'published'
                                                    })

                                        except json.JSONDecodeError:
                                            print(f"Could not decode JSON for file: {file_info.filename}")
                                            continue
                                        except Exception as e:
                                            print(f"Error processing {file_info.filename}: {str(e)}")
                                            continue

                        print(f"Processed {len(cves)} high-risk CVEs from {yesterday_date_str} delta")

        except Exception as e:
            print(f"Error fetching CVEs from CVEProject/cvelistV5: {e}")
            # Fallback to original implementation if the new source fails
            print("Using fallback mechanism...")

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
        """Collect CVEs from the new CVEProject/cvelistV5 source"""
        print(f"Collecting CVEs from the last {days} day(s) from CVEProject/cvelistV5...")

        # Calculate the date for which we need to download the delta (yesterday)
        target_date = datetime.now() - timedelta(days=days)

        # Ensure we don't try to fetch future dates - if target date is today or in the future,
        # go back another day until we find a past date that we can fetch
        while target_date.date() >= datetime.now().date():
            target_date = target_date - timedelta(days=1)

        date_str = target_date.strftime("%Y-%m-%d")
        print(f"Adjusted to fetch CVEs for date: {date_str}")

        # Get CVEs from CVEProject/cvelistV5
        cvelistv5_cves = self.get_cvelistv5_cves_for_date(target_date)
        print(f"Found {len(cvelistv5_cves)} high-risk CVEs from CVEProject/cvelistV5")

        # Combine and deduplicate
        all_cves = {}

        for cve in cvelistv5_cves:
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

    def get_cvelistv5_cves_for_date(self, target_date):
        """Fetch CVEs from CVEProject/cvelistV5 for a specific date"""
        cves = []
        try:
            date_str = target_date.strftime("%Y-%m-%d")

            print(f"Attempting to download CVEs for date: {date_str}")

            # Construct the URL for the delta ZIP file
            zip_url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{date_str}_at_end_of_day/{date_str}_delta_CVEs_at_end_of_day.zip"

            print(f"Downloading from: {zip_url}")

            # Try downloading with the proxy if direct download fails
            try:
                response = requests.get(zip_url, timeout=60)
            except:
                print("Direct download failed, trying with proxy...")
                proxies = {
                    'http': 'http://192.168.17.1:7890',
                    'https': 'https://192.168.17.1:7890'
                }
                try:
                    response = requests.get(zip_url, timeout=60, proxies=proxies)
                except:
                    print("Proxy download failed as well.")
                    return []

            if response.status_code == 200:
                print(f"Successfully downloaded the ZIP file for {date_str}")

                # Create the directory to store the downloaded ZIP
                zip_dir = f"docs/json/{target_date.year}/{target_date.month:02d}"
                os.makedirs(zip_dir, exist_ok=True)

                # Save the ZIP file to the directory
                zip_filename = os.path.join(zip_dir, f"{date_str}_delta_CVEs_at_end_of_day.zip")
                with open(zip_filename, 'wb') as f:
                    f.write(response.content)
                print(f"Saved ZIP file to: {zip_filename}")

                # Extract the ZIP file in memory
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                    print(f"Extracting {len(zip_file.namelist())} files from the ZIP...")

                    for file_info in zip_file.filelist:
                        if file_info.filename.endswith('.json'):
                            # Read the JSON file
                            with zip_file.open(file_info.filename) as json_file:
                                try:
                                    cve_data = json.loads(json_file.read().decode('utf-8'))

                                    # Process the CVE data according to the v5 schema
                                    cve_id = cve_data.get('cveMetadata', {}).get('cveId', '')
                                    if cve_id:
                                        # Extract description
                                        description = ""
                                        descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
                                        for desc in descriptions:
                                            if desc.get('lang') == 'en':
                                                description = desc.get('value', '')
                                                break

                                        # Extract CVSS metrics
                                        cvss_score = 0
                                        metrics = cve_data.get('containers', {}).get('cna', {}).get('metrics', [])
                                        for metric_group in metrics:
                                            # Check for CVSS v4.x
                                            if 'cvssV4_0' in metric_group:
                                                cvss_data = metric_group['cvssV4_0']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            # Check for CVSS v3.x
                                            elif 'cvssV3_1' in metric_group:
                                                cvss_data = metric_group['cvssV3_1']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            elif 'cvssV3_0' in metric_group:
                                                cvss_data = metric_group['cvssV3_0']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            # Check for CVSS v2
                                            elif 'cvssV2_0' in metric_group:
                                                cvss_data = metric_group['cvssV2_0']
                                                cvss_score = cvss_data.get('baseScore', 0)

                                        # Extract vendor and product information from affected
                                        vendors = set()
                                        products = set()

                                        affected_list = cve_data.get('containers', {}).get('cna', {}).get('affected', [])
                                        for affected in affected_list:
                                            vendor = affected.get('vendor', '')
                                            product = affected.get('product', '')

                                            if vendor and vendor.lower() not in ['-', '*', '']:
                                                vendors.add(vendor.lower())
                                            if product and product.lower() not in ['-', '*', '']:
                                                products.add(product.lower())

                                            # Also check for platforms, modules, etc.
                                            platforms = affected.get('platforms', [])
                                            for platform in platforms:
                                                if platform and platform.lower() not in ['-', '*', '']:
                                                    vendors.add(platform.lower())

                                            # Process versions to extract more vendor/product info
                                            versions = affected.get('versions', [])
                                            for version in versions:
                                                if 'changes' in version:
                                                    for change in version['changes']:
                                                        value = change.get('value', '')
                                                        if value and value.lower() not in ['-', '*', '']:
                                                            vendors.add(value.lower())

                                        # Extract publication date
                                        published_date = cve_data.get('cveMetadata', {}).get('datePublished', '')
                                        last_modified = cve_data.get('cveMetadata', {}).get('dateUpdated', '')

                                        # Determine entry type based on dates
                                        target_date_str = target_date.strftime("%Y-%m-%d")
                                        entry_type = 'published'  # Default assumption

                                        # If published date matches target date, it's newly published
                                        if published_date and published_date.startswith(target_date_str):
                                            entry_type = 'published'
                                        # If published earlier but modified on target date, it's modified
                                        elif (published_date and not published_date.startswith(target_date_str) and
                                              last_modified and last_modified.startswith(target_date_str)):
                                            entry_type = 'modified'
                                        # If no published date but has modification on target date, consider as modified
                                        elif (not published_date and last_modified and
                                              last_modified.startswith(target_date_str)):
                                            entry_type = 'modified'
                                        # Otherwise, treat as published if it has data for the target date
                                        else:
                                            entry_type = 'published'

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
                                                'products': list(products),  # Keep products for processing but we'll not use them in the UI
                                                'published_date': published_date,
                                                'last_modified': last_modified,
                                                'entry_type': entry_type
                                            })

                                except json.JSONDecodeError:
                                    print(f"Could not decode JSON for file: {file_info.filename}")
                                    continue
                                except Exception as e:
                                    print(f"Error processing {file_info.filename}: {str(e)}")
                                    continue

                print(f"Processed {len(cves)} high-risk CVEs from {date_str} delta")
            else:
                print(f"Failed to download CVEs for {date_str}. Status code: {response.status_code}")

        except Exception as e:
            print(f"Error fetching CVEs from CVEProject/cvelistV5: {e}")

        return cves
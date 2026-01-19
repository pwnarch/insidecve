"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Checker
Fetches and checks CVEs against CISA's KEV list.
"""

import requests
import json
from datetime import datetime, timedelta
import os

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILE = ".kev_cache.json"
CACHE_DURATION_HOURS = 24

class KEVChecker:
    """Check if CVEs are in CISA's Known Exploited Vulnerabilities catalog."""
    
    def __init__(self):
        self.kev_data = None
        self.kev_cve_set = set()
        self._load_kev_data()
    
    def _load_kev_data(self):
        """Load KEV data from cache or fetch from CISA."""
        # Check if cache exists and is fresh
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f:
                    cached = json.load(f)
                    cache_time = datetime.fromisoformat(cached['cached_at'])
                    if datetime.now() - cache_time < timedelta(hours=CACHE_DURATION_HOURS):
                        self.kev_data = cached['data']
                        self.kev_cve_set = set(cached['cve_ids'])
                        print(f"✓ Loaded {len(self.kev_cve_set)} KEV entries from cache")
                        return
            except Exception as e:
                print(f"Cache read error: {e}")
        
        # Fetch fresh data
        self._fetch_kev_data()
    
    def _fetch_kev_data(self):
        """Fetch KEV catalog from CISA."""
        try:
            print("Fetching CISA KEV catalog...")
            response = requests.get(KEV_URL, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            self.kev_data = data
            
            # Extract CVE IDs
            vulnerabilities = data.get('vulnerabilities', [])
            self.kev_cve_set = {v['cveID'] for v in vulnerabilities if 'cveID' in v}
            
            # Cache the data
            cache_data = {
                'cached_at': datetime.now().isoformat(),
                'data': data,
                'cve_ids': list(self.kev_cve_set)
            }
            
            with open(CACHE_FILE, 'w') as f:
                json.dump(cache_data, f)
            
            print(f"✓ Fetched {len(self.kev_cve_set)} known exploited vulnerabilities")
            
        except Exception as e:
            print(f"✗ Failed to fetch KEV data: {e}")
            self.kev_data = {'vulnerabilities': []}
            self.kev_cve_set = set()
    
    def is_exploited(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        return cve_id in self.kev_cve_set
    
    def get_kev_details(self, cve_id: str) -> dict:
        """Get KEV details for a specific CVE."""
        if not self.is_exploited(cve_id):
            return None
        
        if not self.kev_data:
            return None
        
        for vuln in self.kev_data.get('vulnerabilities', []):
            if vuln.get('cveID') == cve_id:
                return {
                    'vendor': vuln.get('vendorProject'),
                    'product': vuln.get('product'),
                    'name': vuln.get('vulnerabilityName'),
                    'date_added': vuln.get('dateAdded'),
                    'due_date': vuln.get('dueDate'),
                    'required_action': vuln.get('requiredAction'),
                    'notes': vuln.get('notes', '')
                }
        
        return None
    
    def get_all_kev_cves(self):
        """Return set of all KEV CVE IDs."""
        return self.kev_cve_set
    
    def refresh(self):
        """Force refresh KEV data."""
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
        self._fetch_kev_data()


# Singleton instance
_kev_checker = None

def get_kev_checker() -> KEVChecker:
    """Get or create KEV checker singleton."""
    global _kev_checker
    if _kev_checker is None:
        _kev_checker = KEVChecker()
    return _kev_checker

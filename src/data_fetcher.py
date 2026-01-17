import os
import json
import time
import requests
from pathlib import Path

class DataFetcher:
    def __init__(self, cache_dir="cache", nvd_api_key=None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.nvd_api_key = nvd_api_key
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.v5_base_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

    def _get_cache_path(self, cve_id, source):
        return self.cache_dir / f"{cve_id}_{source}.json"

    def _load_from_cache(self, cve_id, source):
        path = self._get_cache_path(cve_id, source)
        if path.exists():
            with open(path, "r") as f:
                return json.load(f)
        return None

    def _save_to_cache(self, cve_id, source, data):
        path = self._get_cache_path(cve_id, source)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def fetch_nvd_cve(self, cve_id):
        # Check cache first
        cached = self._load_from_cache(cve_id, "nvd")
        if cached:
            return cached

        # Rate limiting: NVD allows 50 req/30s with key, 5 req/30s without.
        # Simple sleep to be safe.
        time.sleep(0.6 if self.nvd_api_key else 6)

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        try:
            params = {"cveId": cve_id}
            response = requests.get(self.nvd_base_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("vulnerabilities"):
                # NVD API 2.0 returns a list of vulnerabilities, usually just one
                self._save_to_cache(cve_id, "nvd", data)
                return data
            else:
                print(f"Warning: NVD has no record for {cve_id}")
                return None
        except Exception as e:
            print(f"Error fetching {cve_id} from NVD: {e}")
            return None

    def fetch_v5_cve(self, cve_id):
        cached = self._load_from_cache(cve_id, "v5")
        if cached:
            return cached

        # Construct path: cves/YYYY/XXXXxxx/CVE-YYYY-XXXX.json
        try:
            parts = cve_id.split("-")
            if len(parts) != 3:
                print(f"Invalid CVE ID format: {cve_id}")
                return None
            
            year = parts[1]
            id_num = parts[2]
            
            # directory logic: 1000 -> 1xxx
            group_size = 1000
            # This logic mimics the cvelistV5 structure
            # e.g. CVE-2021-1234 -> 2021/1xxx/CVE-2021-1234.json
            # e.g. CVE-2021-12345 -> 2021/12xxx/CVE-2021-12345.json
            if len(id_num) < 4:
                # Should satisfy the regex format, but just in case
                group = "0xxx" # or something, typically CVE IDs are 4+ digits
            elif len(id_num) == 4:
                 group = f"{id_num[0]}xxx"
            else:
                # for 5+ digits, take the first N-3 digits
                prefix = id_num[:-3]
                group = f"{prefix}xxx"

            url = f"{self.v5_base_url}/{year}/{group}/{cve_id}.json"
            
            response = requests.get(url, timeout=10)
            if response.status_code == 404:
                # Fallback or different grouping check? 
                # cvelistV5 structure is generally strict.
                print(f"CVE V5 not found: {cve_id}")
                return None
            
            response.raise_for_status()
            data = response.json()
            self._save_to_cache(cve_id, "v5", data)
            return data

        except Exception as e:
            print(f"Error fetching {cve_id} from V5: {e}")
            return None

    def fetch_batch_nvd(self, cve_ids):
        results = {}
        for cve_id in cve_ids:
            data = self.fetch_nvd_cve(cve_id)
            if data:
                results[cve_id] = data
        return results

    def fetch_batch_v5(self, cve_ids):
        results = {}
        for cve_id in cve_ids:
            data = self.fetch_v5_cve(cve_id)
            if data:
                results[cve_id] = data
        return results

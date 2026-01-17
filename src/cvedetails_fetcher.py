"""
CVEDetails.com Data Fetcher
Fetches CVE details directly from CVEDetails website using Playwright
"""

from playwright.sync_api import sync_playwright
import re
import time

class CVEDetailsFetcher:
    def __init__(self, headless=True):
        self.base_url = "https://www.cvedetails.com"
        self.headless = headless
    
    def fetch_cve_details(self, cve_ids: list, batch_size=50) -> dict:
        """
        Fetch details for multiple CVEs from CVEDetails.com
        Returns dict: {cve_id: {details}}
        """
        results = {}
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            )
            page = context.new_page()
            
            for idx, cve_id in enumerate(cve_ids, 1):
                print(f"[{idx}/{len(cve_ids)}] Fetching {cve_id} from CVEDetails...")
                
                try:
                    url = f"{self.base_url}/cve/{cve_id}/"
                    page.goto(url, timeout=30000)
                    page.wait_for_load_state("domcontentloaded", timeout=15000)
                    
                    # Small delay to be polite
                    time.sleep(0.5)
                    
                    details = self._extract_details(page, cve_id)
                    results[cve_id] = details
                    
                except Exception as e:
                    print(f"  [WARN] Failed to fetch {cve_id}: {e}")
                    results[cve_id] = {"error": str(e)}
                    
                # Progress indicator
                if idx % 10 == 0:
                    print(f"  Progress: {idx}/{len(cve_ids)} CVEs fetched")
            
            browser.close()
        
        return results
    
    def _extract_details(self, page, cve_id: str) -> dict:
        """Extract CVE details from the page"""
        details = {
            "cve_id": cve_id,
            "description": None,
            "cvss_v31_base_score": None,
            "cvss_v31_severity": None,
            "cvss_vector": None,
            "cwe_id": None,
            "cwe_name": None,
            "published_date": None,
            "last_modified": None,
            "epss_score": None,
            "references": [],
            "affected_products": []
        }
        
        try:
            # Description
            desc_elem = page.locator("div.cvedetailssummary").first
            if desc_elem.is_visible():
                details["description"] = desc_elem.text_content().strip()
            
            # CVSS Score - look for the score badge
            # Try NIST score first
            score_elems = page.locator("div.cvssbox").all()
            for score_elem in score_elems:
                text = score_elem.text_content().strip()
                try:
                    score = float(text)
                    if details["cvss_v31_base_score"] is None:
                        details["cvss_v31_base_score"] = score
                        # Determine severity
                        if score >= 9.0:
                            details["cvss_v31_severity"] = "CRITICAL"
                        elif score >= 7.0:
                            details["cvss_v31_severity"] = "HIGH"
                        elif score >= 4.0:
                            details["cvss_v31_severity"] = "MEDIUM"
                        elif score > 0:
                            details["cvss_v31_severity"] = "LOW"
                        else:
                            details["cvss_v31_severity"] = "NONE"
                except:
                    pass
            
            # CWE
            cwe_links = page.locator("a[href*='/cwe-details/']").all()
            for cwe_link in cwe_links:
                href = cwe_link.get_attribute("href")
                if href:
                    match = re.search(r'/cwe-details/(\d+)/', href)
                    if match:
                        details["cwe_id"] = f"CWE-{match.group(1)}"
                        details["cwe_name"] = cwe_link.text_content().strip()
                        break
            
            # Published Date - find in the page content
            content = page.content()
            
            # Look for publish date pattern
            date_match = re.search(r'Publish Date\s*:\s*(\d{4}-\d{2}-\d{2})', content)
            if date_match:
                details["published_date"] = date_match.group(1)
            
            # EPSS Score
            epss_match = re.search(r'EPSS\s*(?:Score|Percentile)?\s*:?\s*([\d.]+)%', content)
            if epss_match:
                details["epss_score"] = float(epss_match.group(1))
            
            # References
            ref_links = page.locator("table.listtable a[href^='http']").all()
            for ref in ref_links[:10]:  # Limit to 10 refs
                href = ref.get_attribute("href")
                if href and not "cvedetails.com" in href:
                    details["references"].append(href)
            
            # Affected Products - from the page
            prod_rows = page.locator("table#vulnprodstable tr").all()
            for row in prod_rows[1:5]:  # Skip header, limit to 5
                cells = row.locator("td").all()
                if len(cells) >= 3:
                    vendor = cells[1].text_content().strip() if len(cells) > 1 else ""
                    product = cells[2].text_content().strip() if len(cells) > 2 else ""
                    if vendor and product:
                        details["affected_products"].append(f"{vendor} {product}")
            
        except Exception as e:
            print(f"  [WARN] Error extracting details: {e}")
        
        return details


def fetch_from_cvedetails(cve_ids: list) -> dict:
    """
    Convenience function to fetch CVE details from CVEDetails.com
    """
    fetcher = CVEDetailsFetcher(headless=True)
    return fetcher.fetch_cve_details(cve_ids)


if __name__ == "__main__":
    # Test with a few CVEs
    test_cves = ["CVE-2024-28993", "CVE-2024-23476", "CVE-2020-10148"]
    
    results = fetch_from_cvedetails(test_cves)
    
    for cve_id, details in results.items():
        print(f"\n=== {cve_id} ===")
        print(f"  Score: {details.get('cvss_v31_base_score')} ({details.get('cvss_v31_severity')})")
        print(f"  CWE: {details.get('cwe_id')}")
        print(f"  Description: {details.get('description', '')[:100]}...")

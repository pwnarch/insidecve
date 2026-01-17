"""
Vendor Scraper - Fetches vendor list and CVE data from CVEDetails.com
"""

from playwright.sync_api import sync_playwright
import json
import os
import time
from datetime import datetime

CACHE_DIR = "cache"
VENDOR_CACHE_FILE = os.path.join(CACHE_DIR, "vendors.json")

class VendorScraper:
    def __init__(self, headless=True):
        self.base_url = "https://www.cvedetails.com"
        self.headless = headless
        os.makedirs(CACHE_DIR, exist_ok=True)
    
    def get_all_vendors(self, force_refresh=False) -> list:
        """
        Get list of all vendors from A-Z pages.
        Returns: [{"id": "1305", "name": "Solarwinds", "product_count": 78}, ...]
        """
        # Check cache first
        if not force_refresh and os.path.exists(VENDOR_CACHE_FILE):
            cache_age = time.time() - os.path.getmtime(VENDOR_CACHE_FILE)
            if cache_age < 7 * 24 * 3600:  # 7 days
                print("[INFO] Using cached vendor list")
                with open(VENDOR_CACHE_FILE, 'r') as f:
                    return json.load(f)
        
        print("[INFO] Fetching vendor list from CVEDetails (A-Z)...")
        vendors = []
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            )
            page = context.new_page()
            
            # Iterate through A-Z plus numbers/symbols
            chars = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ") + ["0-9"]
            
            for char in chars:
                url = f"{self.base_url}/vendor/firstchar-{char}/"
                print(f"[DEBUG] Fetching vendors starting with '{char}'...")
                
                try:
                    page.goto(url, timeout=30000)
                    page.wait_for_load_state("domcontentloaded")
                    
                    # Handle pagination
                    page_num = 1
                    while True:
                        # Extract vendor links
                        vendor_links = page.locator("a[href*='/vendor/'][href$='.html']").all()
                        
                        for link in vendor_links:
                            href = link.get_attribute("href")
                            name = link.text_content().strip()
                            
                            # Extract vendor ID from href like /vendor/1305/Solarwinds.html
                            if href and "/vendor/" in href and name:
                                parts = href.split("/")
                                for i, part in enumerate(parts):
                                    if part == "vendor" and i + 1 < len(parts):
                                        try:
                                            vendor_id = parts[i + 1]
                                            if vendor_id.isdigit():
                                                vendors.append({
                                                    "id": vendor_id,
                                                    "name": name,
                                                    "url": href
                                                })
                                        except:
                                            pass
                                        break
                        
                        # Check for next page
                        try:
                            next_btn = page.locator("a[title='Next page']").first
                            if next_btn.is_visible():
                                next_btn.click()
                                page.wait_for_load_state("networkidle", timeout=15000)
                                page_num += 1
                            else:
                                break
                        except:
                            break
                    
                except Exception as e:
                    print(f"[WARN] Error fetching char '{char}': {e}")
                    continue
            
            browser.close()
        
        # Dedupe by vendor ID
        seen_ids = set()
        unique_vendors = []
        for v in vendors:
            if v["id"] not in seen_ids:
                seen_ids.add(v["id"])
                unique_vendors.append(v)
        
        # Sort by name
        unique_vendors.sort(key=lambda x: x["name"].lower())
        
        # Cache results
        with open(VENDOR_CACHE_FILE, 'w') as f:
            json.dump(unique_vendors, f, indent=2)
        
        print(f"[INFO] Found {len(unique_vendors)} unique vendors")
        return unique_vendors
    
    def get_vendor_cves(self, vendor_id: str, vendor_name: str) -> dict:
        """
        Scrape all CVEs for a vendor by iterating through their products.
        Returns: {cve_id: {product_names_set}, ...}
        """
        mapping = {}
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            )
            page = context.new_page()
            
            # Get product list pages
            product_list_urls = [
                f"{self.base_url}/product-list/vendor_id-{vendor_id}/{vendor_name}.html",
            ]
            
            # Check for additional pages
            try:
                page.goto(product_list_urls[0], timeout=30000)
                page.wait_for_load_state("networkidle")
                
                # Check if there's pagination
                for i in range(2, 10):  # Check up to 10 pages
                    next_url = f"{self.base_url}/product-list/product_type-/vendor_id-{vendor_id}/firstchar-/page-{i}/products.html"
                    test_page = context.new_page()
                    try:
                        test_page.goto(next_url, timeout=10000)
                        has_products = len(test_page.locator("a[href*='vulnerability-list']").all()) > 0
                        if has_products:
                            product_list_urls.append(next_url)
                        else:
                            break
                    except:
                        break
                    finally:
                        test_page.close()
            except Exception as e:
                print(f"[WARN] Error checking pagination: {e}")
            
            # Collect all product URLs
            product_urls = []
            
            for list_url in product_list_urls:
                print(f"[DEBUG] Scraping product list: {list_url}")
                try:
                    page.goto(list_url, timeout=30000)
                    page.wait_for_load_state("networkidle")
                    
                    product_links = page.locator(f"a[href*='vulnerability-list/vendor_id-{vendor_id}/product_id-']").all()
                    
                    for link in product_links:
                        href = link.get_attribute("href")
                        if href:
                            # Extract product name from URL
                            parts = href.rstrip('.html').split('/')
                            name_slug = parts[-1] if parts else "Unknown"
                            name = name_slug.replace('-', ' ').title()
                            product_urls.append((name, href))
                except Exception as e:
                    print(f"[WARN] Error scraping product list: {e}")
            
            # Dedupe products
            seen_urls = set()
            unique_products = []
            for name, url in product_urls:
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_products.append((name, url))
            
            print(f"[INFO] Found {len(unique_products)} products for {vendor_name}")
            
            # Scrape CVEs from each product
            for idx, (prod_name, rel_url) in enumerate(unique_products, 1):
                full_url = f"{self.base_url}{rel_url}" if rel_url.startswith('/') else rel_url
                print(f"[{idx}/{len(unique_products)}] Scraping: {prod_name}")
                
                try:
                    page.goto(full_url, timeout=30000)
                    page.wait_for_load_state("networkidle")
                    
                    # Paginate through CVEs
                    page_num = 1
                    while True:
                        cve_links = page.locator("a[href^='/cve/CVE-']").all()
                        
                        for clink in cve_links:
                            txt = clink.text_content().strip()
                            if txt.startswith("CVE-"):
                                if txt not in mapping:
                                    mapping[txt] = set()
                                mapping[txt].add(prod_name)
                        
                        # Next page
                        try:
                            next_btn = page.locator("a[title='Next page']").first
                            if next_btn.is_visible():
                                next_btn.click()
                                page.wait_for_load_state("networkidle", timeout=15000)
                                page_num += 1
                            else:
                                break
                        except:
                            break
                            
                except Exception as e:
                    print(f"[WARN] Error scraping {prod_name}: {e}")
                    continue
            
            browser.close()
        
        print(f"[INFO] Found {len(mapping)} unique CVEs for {vendor_name}")
        return mapping


def get_cached_vendors():
    """Quick access to cached vendor list"""
    if os.path.exists(VENDOR_CACHE_FILE):
        with open(VENDOR_CACHE_FILE, 'r') as f:
            return json.load(f)
    return []


if __name__ == "__main__":
    scraper = VendorScraper(headless=True)
    
    # Test: Get vendors starting with 'S'
    print("Testing vendor list fetch...")
    vendors = scraper.get_all_vendors()
    print(f"Total vendors: {len(vendors)}")
    
    # Show first 10
    for v in vendors[:10]:
        print(f"  {v['name']} (ID: {v['id']})")

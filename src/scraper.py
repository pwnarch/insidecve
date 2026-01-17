from playwright.sync_api import sync_playwright
import time
import re

class CWEDetailsScraper:
    def __init__(self, vendor_id="1305", vendor_name="Solarwinds", headless=True):
        self.vendor_id = vendor_id
        self.vendor_name = vendor_name
        self.base_url = "https://www.cvedetails.com"
        self.headless = headless

    def scrape_product_map(self):
        """
        Returns a dict: {cve_id: {product_names_set}}
        """
        mapping = {}
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            page = context.new_page()

            # 1. Get List of Products
            # URL: https://www.cvedetails.com/product-list/vendor_id-1305/Solarwinds.html
            products_url = f"{self.base_url}/product-list/vendor_id-{self.vendor_id}/{self.vendor_name}.html"
            print(f"[DEBUG] Navigating to Product List: {products_url}")
            
            try:
                page.goto(products_url, timeout=60000)
                page.wait_for_load_state("networkidle")
                print(f"[DEBUG] Product list page loaded successfully")
            except Exception as e:
                print(f"[ERROR] Failed to load product list: {e}")
                browser.close()
                return mapping

            # Get all product links from BOTH pages (hardcoded URLs)
            # Page 1 and Page 2 of the product list
            product_list_urls = [
                f"{self.base_url}/product-list/vendor_id-{self.vendor_id}/{self.vendor_name}.html",
                f"{self.base_url}/product-list/product_type-/vendor_id-{self.vendor_id}/firstchar-/page-2/products.html"
            ]
            
            product_urls = []
            
            for page_num, list_url in enumerate(product_list_urls, 1):
                print(f"[DEBUG] Scraping product list page {page_num}: {list_url}")
                try:
                    page.goto(list_url, timeout=60000)
                    page.wait_for_load_state("networkidle")
                except Exception as e:
                    print(f"[WARN] Failed to load product list page {page_num}: {e}")
                    continue
                    
                product_links = page.locator("a[href*='vulnerability-list/vendor_id-1305/product_id-']").all()
                print(f"[DEBUG] Found {len(product_links)} product links on page {page_num}")
                
                # Extract hrefs and names
                # Note: The link TEXT on this page is often the vulnerability COUNT, not the name.
                # We extract the name from the URL path instead.
                for link in product_links:
                    href = link.get_attribute("href")
                    if href:
                        # Extract product name from URL like:
                        # /vulnerability-list/vendor_id-1305/product_id-64841/Solarwinds-Dameware-Mini-Remote-Control.html
                        # Take the last path segment before .html
                        parts = href.rstrip('.html').split('/')
                        if parts:
                            name_slug = parts[-1]  # e.g. "Solarwinds-Dameware-Mini-Remote-Control"
                            # Convert slug to readable name
                            name = name_slug.replace('-', ' ').title()
                        else:
                            name = "Unknown"
                        product_urls.append((name, href))

            # Dedupe by URL (name might have minor variations)
            seen_urls = set()
            unique_products = []
            for name, url in product_urls:
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_products.append((name, url))
            product_urls = unique_products
            print(f"[INFO] Total unique products to scrape: {len(product_urls)}")

            # 2. Visit each product page and get CVEs
            for idx, (prod_name, rel_url) in enumerate(product_urls, 1):
                full_url = f"{self.base_url}{rel_url}"
                print(f"\n[INFO] [{idx}/{len(product_urls)}] Scraping Product: {prod_name}")
                print(f"[DEBUG]   URL: {full_url}")
                
                try:
                    page.goto(full_url, timeout=30000)
                    print(f"[DEBUG]   Page loaded, current URL: {page.url}")
                    
                    # check if we need to click "Browse all vulnerabilities" or similar
                    # Often product pages list versions. We want the full list.
                    # Look for a link containing 'vulnerability-list' which is distinct from 'product-list' or 'version-list'
                    try:
                        vuln_link = page.locator("a[href*='vulnerability-list/vendor_id-1305/product_id-']").first
                        if vuln_link.is_visible():
                            href = vuln_link.get_attribute("href")
                            print(f"[DEBUG]   Found vulnerability list link: {href}")
                            vuln_link.click()
                            page.wait_for_load_state("networkidle", timeout=30000)
                            print(f"[DEBUG]   Navigated to: {page.url}")
                        else:
                            print(f"[DEBUG]   No separate vulnerability link found, already on vuln list")
                    except Exception as nav_e:
                         # It's possible we are already on the right page or no link exists
                         print(f"[WARN]   Navigation issue (might already be there): {nav_e}")

                    # Pagination for CVEs
                    # We might just grab the first page or two.
                    # Ideally loop through pages.
                    
                    page_num = 1
                    while True:
                        # Extract CVEs
                        cve_links = page.locator("a[href^='/cve/CVE-']").all()
                        found_cnt = 0
                        for clink in cve_links:
                            txt = clink.text_content().strip()
                            if txt.startswith("CVE-"):
                                if txt not in mapping:
                                    mapping[txt] = set()
                                mapping[txt].add(prod_name)
                                found_cnt += 1
                        
                        print(f"[DEBUG]   Page {page_num}: Found {found_cnt} CVEs (Total unique so far: {len(mapping)})")
                        
                        # Next page?
                        # Using click() as requested for robust pagination
                        try:
                            next_btn = page.locator("a[title='Next page']").first
                            if next_btn.is_visible():
                                print(f"[DEBUG]   Clicking 'Next page' button...")
                                next_btn.click()
                                page.wait_for_load_state("networkidle", timeout=30000)
                                page_num += 1
                                # Continue loop
                            else:
                                print(f"[DEBUG]   No more pages for this product.")
                                break
                        except Exception as e:
                            print(f"[WARN]   Pagination error: {e}")
                            break

                except Exception as e:
                    print(f"[ERROR] Failed to scrape {prod_name}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue

            browser.close()
            
        return mapping

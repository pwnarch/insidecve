import argparse
import sys
from pathlib import Path
from src.data_fetcher import DataFetcher
from src.normalizer import Normalizer
from src.storage import Storage
from src.scraper import CWEDetailsScraper

def load_cve_ids(filepath):
    path = Path(filepath)
    if not path.exists():
        print(f"Error: {filepath} not found.")
        sys.exit(1)
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip().startswith("CVE-")]

def main():
    parser = argparse.ArgumentParser(description="SolarWinds CVE Pipeline")
    parser.add_argument("--input", default="solarwinds_cve_ids.txt", help="Input file with CVE IDs")
    parser.add_argument("--scrape", action="store_true", help="Enable scraping of CVEDetails (slow)")
    parser.add_argument("--nvd-key", help="NVD API Key", default=None)
    parser.add_argument("--db", default="solarwinds_cves.duckdb", help="Database file path")
    
    args = parser.parse_args()

    # 1. Load IDs
    print("Loading CVE IDs...")
    cve_ids = load_cve_ids(args.input)
    print(f"Loaded {len(cve_ids)} CVE IDs.")

    # 2. Scrape (Optional)
    scraped_data = {}
    if args.scrape:
        print("Starting Scraper (this may take a while)...")
        scraper = CWEDetailsScraper()
        scraped_data = scraper.scrape_product_map()
        print(f"Scraped mappings for {len(scraped_data)} CVEs.")

    # 3. Setup Components
    fetcher = DataFetcher(nvd_api_key=args.nvd_key)
    normalizer = Normalizer()
    storage = Storage(db_path=args.db)

    # Merge Scraped CVEs into List
    if scraped_data:
        scraped_ids = list(scraped_data.keys())
        print(f"Adding {len(scraped_ids)} scraped CVEs to processing list.")
        # Deduplicate
        cve_ids = sorted(list(set(cve_ids + scraped_ids)))
        print(f"Total CVEs to process: {len(cve_ids)}")

    # 4. Process Loop
    print("Fetching and Processing CVEs...")
    for idx, cve_id in enumerate(cve_ids):
        print(f"[{idx+1}/{len(cve_ids)}] Processing {cve_id}...", end="\r")
        
        # Fetch
        nvd = fetcher.fetch_nvd_cve(cve_id)
        v5 = fetcher.fetch_v5_cve(cve_id)
        
        if not nvd and not v5:
            # print(f"  Warning: No data found for {cve_id}")
            continue

        # Normalize
        record = normalizer.normalize(cve_id, nvd, v5)

        # Enrich with Scraped Data
        if cve_id in scraped_data:
            extra_products = scraped_data[cve_id]
            # Format: fake CPE or just append names?
            # Storage expects CPE-ish string for splitting.
            # Let's clean names and append as "cpe:2.3:a:solarwinds:CLEAN_NAME:*:..."
            current_prods = record["products"]
            new_prods = []
            for prod in extra_products:
                clean_prod = prod.replace(" ", "_").lower()
                fake_cpe = f"cpe:2.3:a:solarwinds:{clean_prod}:*:*:*:*:*:*:*"
                new_prods.append(fake_cpe)
            
            if current_prods:
                record["products"] = current_prods + ";" + ";".join(new_prods)
            else:
                record["products"] = ";".join(new_prods)

        # Store
        storage.save_cve(record)

    print("\nProcessing complete.")

    # 5. Export
    print("Exporting data...")
    storage.export_parquet()
    storage.export_csv()
    storage.close()
    print("Done! Data saved to DuckDB, Parquet, and CSV.")

if __name__ == "__main__":
    main()

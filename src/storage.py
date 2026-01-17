import duckdb
import pandas as pd
from pathlib import Path
from datetime import datetime

class Storage:
    def __init__(self, db_path="cve_dashboard.duckdb"):
        self.db_path = db_path
        self.con = duckdb.connect(self.db_path)
        self._init_schema()

    def _init_schema(self):
        # Vendor Metadata table (tracks which vendors have been fetched)
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS vendor_metadata (
                vendor_id VARCHAR PRIMARY KEY,
                vendor_name VARCHAR,
                cve_count INTEGER DEFAULT 0,
                product_count INTEGER DEFAULT 0,
                last_updated TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Main CVEs table - now with vendor tracking
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id VARCHAR PRIMARY KEY,
                vendor_id VARCHAR,
                published_date TIMESTAMP,
                last_modified_date TIMESTAMP,
                description_en VARCHAR,
                source_flags VARCHAR,
                cvss_v31_base_score DOUBLE,
                cvss_v31_severity VARCHAR,
                cvss_v31_vector VARCHAR,
                cvss_v4_base_score DOUBLE,
                cvss_v4_severity VARCHAR,
                cvss_v4_vector VARCHAR
            )
        """)
        
        # Weaknesses (Many-to-Many)
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS weaknesses (
                cve_id VARCHAR,
                cwe_id VARCHAR,
                PRIMARY KEY (cve_id, cwe_id)
            )
        """)

        # References (Many-to-Many)
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS cve_references (
                cve_id VARCHAR,
                url VARCHAR
            )
        """)

        # Products (Many-to-Many)
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS products (
                cve_id VARCHAR,
                raw_cpe VARCHAR,
                vendor VARCHAR,
                product VARCHAR,
                version VARCHAR
            )
        """)
        
        # Create a view for easy flat access
        self.con.execute("""
            CREATE OR REPLACE VIEW flat_cves AS
            SELECT 
                c.*,
                LIST(DISTINCT w.cwe_id) as cwe_list,
                LIST(DISTINCT p.product) as product_list
            FROM cves c
            LEFT JOIN weaknesses w ON c.cve_id = w.cve_id
            LEFT JOIN products p ON c.cve_id = p.cve_id
            GROUP BY c.cve_id, c.vendor_id, c.published_date, c.last_modified_date, c.description_en,
                     c.source_flags, c.cvss_v31_base_score, c.cvss_v31_severity, c.cvss_v31_vector,
                     c.cvss_v4_base_score, c.cvss_v4_severity, c.cvss_v4_vector
        """)

    # --- Vendor Metadata Methods ---
    
    def get_fetched_vendors(self):
        """Get list of vendors that have been fetched"""
        try:
            return self.con.execute("""
                SELECT vendor_id, vendor_name, cve_count, product_count, last_updated 
                FROM vendor_metadata 
                ORDER BY vendor_name
            """).fetchdf()
        except:
            return pd.DataFrame()
    
    def update_vendor_metadata(self, vendor_id, vendor_name, cve_count, product_count):
        """Update or insert vendor metadata"""
        self.con.execute("""
            INSERT OR REPLACE INTO vendor_metadata 
            (vendor_id, vendor_name, cve_count, product_count, last_updated)
            VALUES (?, ?, ?, ?, ?)
        """, (vendor_id, vendor_name, cve_count, product_count, datetime.now()))
    
    def get_existing_cve_ids(self, vendor_id=None):
        """Get list of CVE IDs already in database, optionally filtered by vendor"""
        if vendor_id:
            result = self.con.execute(
                "SELECT cve_id FROM cves WHERE vendor_id = ?", (vendor_id,)
            ).fetchall()
        else:
            result = self.con.execute("SELECT cve_id FROM cves").fetchall()
        return set(row[0] for row in result)
    
    def get_cves_by_vendor(self, vendor_id):
        """Get all CVEs for a specific vendor"""
        return self.con.execute("""
            SELECT * FROM flat_cves WHERE vendor_id = ?
        """, (vendor_id,)).fetchdf()

    def save_cve(self, record, vendor_id=None):
        # 1. Upsert CVE
        self.con.execute("""
            INSERT OR REPLACE INTO cves VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["cve_id"],
            vendor_id or record.get("vendor_id"),
            record["published_date"],
            record["last_modified_date"],
            record["description_en"],
            record["source_flags"],
            record["cvss_v31_base_score"],
            record["cvss_v31_severity"],
            record["cvss_v31_vector"],
            record["cvss_v4_base_score"],
            record["cvss_v4_severity"],
            record["cvss_v4_vector"]
        ))

        cve_id = record["cve_id"]

        # 2. Update Weaknesses
        self.con.execute("DELETE FROM weaknesses WHERE cve_id = ?", (cve_id,))
        if record.get("cwe_ids"):
            cwes = record["cwe_ids"].split(",")
            for cwe in cwes:
                if cwe.strip():
                    self.con.execute("INSERT OR IGNORE INTO weaknesses VALUES (?, ?)", (cve_id, cwe.strip()))

        # 3. Update References
        self.con.execute("DELETE FROM cve_references WHERE cve_id = ?", (cve_id,))
        if record.get("reference_urls"):
            urls = record["reference_urls"].split(",")
            for url in urls:
                if url.strip():
                    self.con.execute("INSERT INTO cve_references VALUES (?, ?)", (cve_id, url.strip()))

        # 4. Update Products
        self.con.execute("DELETE FROM products WHERE cve_id = ?", (cve_id,))
        if record.get("products"):
            products = record["products"].split(";")
            unique_products = set()
            for prod in products:
                if not prod.strip():
                    continue
                # Simple CPE 2.3 parser
                parts = prod.split(":")
                vendor = parts[3] if len(parts) > 3 else "unknown"
                product_name = parts[4] if len(parts) > 4 else "unknown"
                version = parts[5] if len(parts) > 5 else "unknown"
                
                key = (cve_id, prod, vendor, product_name, version)
                if key not in unique_products:
                    self.con.execute("INSERT INTO products VALUES (?, ?, ?, ?, ?)", key)
                    unique_products.add(key)

    def add_product_mapping(self, cve_id, product_name, vendor_name=""):
        """Add a simple product mapping from scraper"""
        self.con.execute("""
            INSERT INTO products (cve_id, raw_cpe, vendor, product, version)
            VALUES (?, ?, ?, ?, ?)
        """, (cve_id, "", vendor_name, product_name, "*"))

    def export_parquet(self, filepath="cve_dashboard.parquet", vendor_id=None):
        if vendor_id:
            df = self.get_cves_by_vendor(vendor_id)
        else:
            df = self.con.execute("SELECT * FROM flat_cves").fetchdf()
        df.to_parquet(filepath)

    def export_csv(self, filepath="cve_dashboard.csv", vendor_id=None):
        if vendor_id:
            df = self.get_cves_by_vendor(vendor_id)
        else:
            df = self.con.execute("SELECT * FROM flat_cves").fetchdf()
        df.to_csv(filepath, index=False)

    def close(self):
        self.con.close()

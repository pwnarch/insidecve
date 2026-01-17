import duckdb
import pandas as pd
from pathlib import Path

class Storage:
    def __init__(self, db_path="solarwinds_cves.duckdb"):
        self.db_path = db_path
        self.con = duckdb.connect(self.db_path)
        self._init_schema()

    def _init_schema(self):
        # Main CVEs table
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id VARCHAR PRIMARY KEY,
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
                LIST(w.cwe_id) as cwe_list,
                LIST(p.product) as product_list
            FROM cves c
            LEFT JOIN weaknesses w ON c.cve_id = w.cve_id
            LEFT JOIN products p ON c.cve_id = p.cve_id
            GROUP BY c.cve_id, c.published_date, c.last_modified_date, c.description_en,
                     c.source_flags, c.cvss_v31_base_score, c.cvss_v31_severity, c.cvss_v31_vector,
                     c.cvss_v4_base_score, c.cvss_v4_severity, c.cvss_v4_vector
        """)

    def save_cve(self, record):
        # 1. Upsert CVE
        self.con.execute("""
            INSERT OR REPLACE INTO cves VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["cve_id"],
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
        if record["cwe_ids"]:
            cwes = record["cwe_ids"].split(",")
            for cwe in cwes:
                if cwe.strip():
                    self.con.execute("INSERT OR IGNORE INTO weaknesses VALUES (?, ?)", (cve_id, cwe.strip()))

        # 3. Update References
        self.con.execute("DELETE FROM cve_references WHERE cve_id = ?", (cve_id,))
        if record["reference_urls"]:
            urls = record["reference_urls"].split(",")
            for url in urls:
                if url.strip():
                    self.con.execute("INSERT INTO cve_references VALUES (?, ?)", (cve_id, url.strip()))

        # 4. Update Products
        self.con.execute("DELETE FROM products WHERE cve_id = ?", (cve_id,))
        if record["products"]:
            products = record["products"].split(";")
            unique_products = set()
            for prod in products:
                if not prod.strip():
                    continue
                # Simple CPE 2.3 parser
                # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                parts = prod.split(":")
                vendor = parts[3] if len(parts) > 3 else "unknown"
                product_name = parts[4] if len(parts) > 4 else "unknown"
                version = parts[5] if len(parts) > 5 else "unknown"
                
                # Deduplicate roughly
                key = (cve_id, prod, vendor, product_name, version)
                if key not in unique_products:
                    self.con.execute("INSERT INTO products VALUES (?, ?, ?, ?, ?)", key)
                    unique_products.add(key)

    def export_parquet(self, filepath="solarwinds_cves.parquet"):
        # Export the flat view
        df = self.con.execute("SELECT * FROM flat_cves").fetchdf()
        df.to_parquet(filepath)

    def export_csv(self, filepath="solarwinds_cves.csv"):
        df = self.con.execute("SELECT * FROM flat_cves").fetchdf()
        df.to_csv(filepath, index=False)

    def close(self):
        self.con.close()

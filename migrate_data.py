#!/usr/bin/env python3
"""Migrate SolarWinds data from old DB to new multi-vendor DB"""

import duckdb
from datetime import datetime
import sys

VENDOR_ID = "1305"
VENDOR_NAME = "Solarwinds"

def migrate():
    print("=" * 50)
    print("Migrating SolarWinds data from old DB...")
    print("=" * 50)
    
    # Check old DB
    try:
        old_con = duckdb.connect('solarwinds_cves.duckdb', read_only=True)
        old_count = old_con.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
        print(f"[OLD DB] Found {old_count} CVEs")
    except Exception as e:
        print(f"Error: Old DB not found or empty: {e}")
        sys.exit(1)
    
    # Connect to new DB
    new_con = duckdb.connect('cve_dashboard.duckdb')
    
    # Ensure schema exists
    new_con.execute("""
        CREATE TABLE IF NOT EXISTS vendor_metadata (
            vendor_id VARCHAR PRIMARY KEY,
            vendor_name VARCHAR,
            cve_count INTEGER DEFAULT 0,
            product_count INTEGER DEFAULT 0,
            last_updated TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Check if CVEs table has vendor_id
    try:
        new_con.execute("SELECT vendor_id FROM cves LIMIT 1")
    except:
        print("[NEW DB] Adding vendor_id column to cves table...")
        new_con.execute("ALTER TABLE cves ADD COLUMN vendor_id VARCHAR")
    
    # Migrate CVEs
    print("\n[MIGRATING] CVEs...")
    cves = old_con.execute("SELECT * FROM cves").fetchdf()
    migrated = 0
    for _, row in cves.iterrows():
        try:
            new_con.execute("""
                INSERT OR REPLACE INTO cves 
                (cve_id, vendor_id, published_date, last_modified_date, description_en, source_flags,
                 cvss_v31_base_score, cvss_v31_severity, cvss_v31_vector,
                 cvss_v4_base_score, cvss_v4_severity, cvss_v4_vector)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                row['cve_id'], VENDOR_ID, row['published_date'], row['last_modified_date'],
                row['description_en'], row.get('source_flags', 'nvd'),
                row['cvss_v31_base_score'], row['cvss_v31_severity'], row['cvss_v31_vector'],
                row.get('cvss_v4_base_score'), row.get('cvss_v4_severity'), row.get('cvss_v4_vector')
            ))
            migrated += 1
        except Exception as e:
            print(f"  Error migrating {row['cve_id']}: {e}")
    print(f"  Migrated {migrated} CVEs")
    
    # Migrate products
    print("\n[MIGRATING] Products...")
    products = old_con.execute("SELECT * FROM products").fetchdf()
    prod_migrated = 0
    for _, row in products.iterrows():
        try:
            new_con.execute("""
                INSERT INTO products (cve_id, raw_cpe, vendor, product, version)
                VALUES (?, ?, ?, ?, ?)
            """, (row['cve_id'], row.get('raw_cpe', ''), VENDOR_NAME, row['product'], row.get('version', '*')))
            prod_migrated += 1
        except:
            pass
    print(f"  Migrated {prod_migrated} product mappings")
    
    # Migrate weaknesses
    print("\n[MIGRATING] Weaknesses...")
    weaknesses = old_con.execute("SELECT * FROM weaknesses").fetchdf()
    cwe_migrated = 0
    for _, row in weaknesses.iterrows():
        try:
            new_con.execute("INSERT OR IGNORE INTO weaknesses VALUES (?, ?)", (row['cve_id'], row['cwe_id']))
            cwe_migrated += 1
        except:
            pass
    print(f"  Migrated {cwe_migrated} weakness mappings")
    
    # Update vendor metadata
    print("\n[UPDATING] Vendor metadata...")
    cve_count = new_con.execute(f"SELECT COUNT(*) FROM cves WHERE vendor_id = '{VENDOR_ID}'").fetchone()[0]
    prod_count = len(products['product'].unique())
    
    new_con.execute("""
        INSERT OR REPLACE INTO vendor_metadata (vendor_id, vendor_name, cve_count, product_count, last_updated)
        VALUES (?, ?, ?, ?, ?)
    """, (VENDOR_ID, VENDOR_NAME, cve_count, prod_count, datetime.now()))
    
    # Verify
    print("\n" + "=" * 50)
    print("MIGRATION COMPLETE")
    print("=" * 50)
    result = new_con.execute("SELECT * FROM vendor_metadata").fetchall()
    print(f"Vendor Metadata: {result}")
    
    new_cve_count = new_con.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    print(f"Total CVEs in new DB: {new_cve_count}")
    
    old_con.close()
    new_con.close()
    
    print("\n✅ SolarWinds data migrated successfully!")
    print("   Refresh the Streamlit app to see the data.")

if __name__ == "__main__":
    migrate()

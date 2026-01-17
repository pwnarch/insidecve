import duckdb

def clean():
    con = duckdb.connect("solarwinds_cves.duckdb")
    
    # Check count before
    cnt_before = con.execute("SELECT count(*) FROM products").fetchone()[0]
    print(f"Products before cleanup: {cnt_before}")
    
    # Delete numeric products (some scraper artifacts usually < 100 or huge numbers)
    # We'll use a regex to identify products that are ONLY digits
    # syntax: regexp_matches(product, '^[0-9]+$')
    
    # DuckDB regex match
    con.execute("DELETE FROM products WHERE regexp_matches(product, '^[0-9]+$')")
    
    cnt_after = con.execute("SELECT count(*) FROM products").fetchone()[0]
    print(f"Products after cleanup: {cnt_after}")
    print(f"Removed {cnt_before - cnt_after} records.")
    
    con.close()

if __name__ == "__main__":
    clean()

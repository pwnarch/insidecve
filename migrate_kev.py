"""
Migration script to add is_kev column to existing databases
Run this once to update your schema.
"""
import duckdb

def migrate_add_kev_column(db_path="cve_dashboard.duckdb"):
    """Add is_kev column to existing cves table if it doesn't exist."""
    con = duckdb.connect(db_path)
    
    try:
        # Check if column exists
        columns = con.execute("PRAGMA table_info(cves)").fetchdf()
        if 'is_kev' not in columns['name'].values:
            print("Adding is_kev column to cves table...")
            con.execute("ALTER TABLE cves ADD COLUMN is_kev BOOLEAN DEFAULT FALSE")
            print("✓ Successfully added is_kev column")
        else:
            print("✓ is_kev column already exists")
    except Exception as e:
        print(f"✗ Error during migration: {e}")
    finally:
        con.close()

if __name__ == "__main__":
    migrate_add_kev_column()

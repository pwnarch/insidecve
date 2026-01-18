
import duckdb
import requests
import re
import time
from src.storage import Storage

def fetch_cwe_name(cwe_id):
    if not cwe_id.startswith('CWE-'):
        return cwe_id
    
    id_num = cwe_id.split('-')[1]
    url = f"https://cwe.mitre.org/data/definitions/{id_num}.html"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            # Simple regex to find title
            match = re.search(r'<h2[^>]*>CWE-\d+:(.+?)</h2>', r.text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    except Exception as e:
        print(f"Error fetching {cwe_id}: {e}")
    return None

def main():
    # Connect directly in read-only mode
    try:
        con = duckdb.connect('cve_dashboard.duckdb', read_only=True)
        cwes = con.execute("SELECT DISTINCT cwe_id FROM weaknesses").fetchall()
        unique_cwes = [c[0] for c in cwes if c[0]]
    except Exception as e:
        print(f"DB Error: {e}")
        return
    
    print(f"Found {len(unique_cwes)} unique CWEs.")
    
    cwe_map = {}
    for cwe in unique_cwes:
        print(f"Fetching {cwe}...")
        name = fetch_cwe_name(cwe)
        if name:
            cwe_map[cwe] = name
            print(f"  -> {name}")
        else:
            print(f"  -> Failed")
        time.sleep(0.5) # Be nice to MITRE
        
    # Write to file
    with open('cwe_metadata_update.txt', 'w') as f:
        f.write("CWE_METADATA_UPDATE = {\n")
        for cwe, name in sorted(cwe_map.items()):
            # Try to guess category (simplified)
            cat = 'Other'
            lower = name.lower()
            if 'injection' in lower: cat = 'Injection'
            elif 'buffer' in lower or 'memory' in lower or 'pointer' in lower: cat = 'Memory'
            elif 'authentication' in lower: cat = 'Authentication'
            elif 'authorization' in lower or 'access control' in lower or 'privilege' in lower: cat = 'Access Control'
            elif 'exposure' in lower or 'disclosure' in lower: cat = 'Information'
            elif 'input' in lower or 'validation' in lower: cat = 'Input Validation'
            elif 'cryptographic' in lower: cat = 'Cryptography'
            elif 'site scripting' in lower: cat = 'Injection' # XSS
            
            f.write(f"    '{cwe}': {{'name': '{name}', 'category': '{cat}'}},\n")
        f.write("}\n")
    print("Done writing to cwe_metadata_update.txt")

if __name__ == "__main__":
    main()

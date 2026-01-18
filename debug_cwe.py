
print("Script started...")
import duckdb
import requests
import re
import time
import sys

def fetch_names():
    print("Connecting to DB...")
    try:
        con = duckdb.connect('cve_dashboard.duckdb', read_only=True)
        print("Connected.")
        cwes_res = con.execute("SELECT DISTINCT cwe_id FROM weaknesses").fetchall()
        print(f"Query returned {len(cwes_res)} rows.")
        unique_cwes = [c[0] for c in cwes_res if c[0]]
    except Exception as e:
        print(f"DB Error: {e}")
        return

    print(f"Found {len(unique_cwes)} unique CWEs to fetch.")
    
    with open('cwe_metadata_update.txt', 'w') as f:
        f.write("CWE_METADATA_UPDATE = {\n")
        
        for cwe in unique_cwes:
            if not cwe.startswith('CWE-'): continue
            
            id_num = cwe.split('-')[1]
            url = f"https://cwe.mitre.org/data/definitions/{id_num}.html"
            print(f"Fetching {cwe}...", end=' ')
            sys.stdout.flush()
            
            name = cwe
            try:
                r = requests.get(url, timeout=3)
                if r.status_code == 200:
                    match = re.search(r'<h2[^>]*>CWE-\d+:(.+?)</h2>', r.text, re.IGNORECASE)
                    if match:
                        name = match.group(1).strip()
                        print(f"Found: {name}")
                    else:
                        print("No name in HTML")
                else:
                    print(f"HTTP {r.status_code}")
            except Exception as e:
                print(f"Err: {e}")
            
            # Category guess
            cat = 'Other'
            lower = name.lower()
            if 'injection' in lower: cat = 'Injection'
            elif 'buffer' in lower or 'memory' in lower: cat = 'Memory'
            elif 'auth' in lower or 'access' in lower: cat = 'Access Control'
            elif 'input' in lower: cat = 'Input Validation'
            elif 'exposure' in lower: cat = 'Information'
            
            f.write(f"    '{cwe}': {{'name': '{name}', 'category': '{cat}'}},\n")
            f.flush()
            time.sleep(0.2)
            
        f.write("}\n")
    print("Finished.")

if __name__ == "__main__":
    fetch_names()

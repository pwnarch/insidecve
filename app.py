"""
CVE Intelligence Dashboard
Select any vendor, build their vulnerability database, and analyze security trends.
"""

import streamlit as st
import pandas as pd
import duckdb
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.storage import Storage
from src.vendor_scraper import VendorScraper, get_cached_vendors
from src.cvedetails_fetcher import CVEDetailsFetcher

st.set_page_config(
    page_title="CVE Dashboard", 
    page_icon="🔒",
    layout="wide"
)

# --- Session State ---
if 'building' not in st.session_state:
    st.session_state.building = False
if 'build_progress' not in st.session_state:
    st.session_state.build_progress = ""

# --- Database Connection ---
@st.cache_resource
def get_storage():
    return Storage(db_path="cve_dashboard.duckdb")

# --- Vendor List ---
@st.cache_data(ttl=3600)
def load_vendor_list():
    """Load cached vendor list or return empty"""
    vendors = get_cached_vendors()
    if vendors:
        return vendors
    return []

# --- Helper Functions ---
def build_vendor_data(vendor_id: str, vendor_name: str, update_only: bool = False):
    """Scrape and store CVE data for a vendor"""
    storage = get_storage()
    
    # Get existing CVEs if updating
    existing_cves = set()
    if update_only:
        existing_cves = storage.get_existing_cve_ids(vendor_id)
        st.info(f"Found {len(existing_cves)} existing CVEs. Checking for new ones...")
    
    # Scrape CVEs
    with st.spinner(f"Scraping CVEs for {vendor_name}..."):
        scraper = VendorScraper(headless=True)
        cve_mapping = scraper.get_vendor_cves(vendor_id, vendor_name)
    
    if not cve_mapping:
        st.error("No CVEs found for this vendor.")
        return
    
    # Filter to new CVEs only if updating
    cve_ids = list(cve_mapping.keys())
    if update_only:
        new_cves = [c for c in cve_ids if c not in existing_cves]
        st.info(f"Found {len(new_cves)} new CVEs to fetch.")
        cve_ids = new_cves
    
    if not cve_ids:
        st.success("Database is already up to date!")
        return
    
    # Fetch details from CVEDetails
    with st.spinner(f"Fetching details for {len(cve_ids)} CVEs..."):
        fetcher = CVEDetailsFetcher(headless=True)
        details = fetcher.fetch_cve_details(cve_ids)
    
    # Store in database
    with st.spinner("Saving to database..."):
        product_count = len(set(p for prods in cve_mapping.values() for p in prods))
        
        for cve_id, data in details.items():
            if "error" in data:
                continue
                
            record = {
                "cve_id": cve_id,
                "vendor_id": vendor_id,
                "published_date": data.get("published_date"),
                "last_modified_date": data.get("last_modified"),
                "description_en": data.get("description"),
                "source_flags": "cvedetails",
                "cvss_v31_base_score": data.get("cvss_v31_base_score"),
                "cvss_v31_severity": data.get("cvss_v31_severity"),
                "cvss_v31_vector": data.get("cvss_vector"),
                "cvss_v4_base_score": None,
                "cvss_v4_severity": None,
                "cvss_v4_vector": None,
                "cwe_ids": data.get("cwe_id", ""),
                "reference_urls": ",".join(data.get("references", [])[:5]),
                "products": ""
            }
            storage.save_cve(record, vendor_id)
            
            # Add product mappings
            if cve_id in cve_mapping:
                for prod in cve_mapping[cve_id]:
                    storage.add_product_mapping(cve_id, prod, vendor_name)
        
        # Update metadata
        total_cves = len(storage.get_existing_cve_ids(vendor_id))
        storage.update_vendor_metadata(vendor_id, vendor_name, total_cves, product_count)
    
    st.success(f"✅ Successfully processed {len(details)} CVEs for {vendor_name}!")
    st.cache_data.clear()

# --- Main App ---
st.title("CVE  Dashboard")
st.caption("Select any vendor, build their vulnerability database, and analyze security trends.")

# --- Sidebar: Company Selection ---
st.sidebar.header("📊 Data Management")

# Load vendors
vendors = load_vendor_list()
storage = get_storage()
fetched_vendors_df = storage.get_fetched_vendors()

# Show fetched vendors first
st.sidebar.subheader("Your Companies")
if not fetched_vendors_df.empty:
    for _, row in fetched_vendors_df.iterrows():
        col1, col2 = st.sidebar.columns([3, 1])
        col1.write(f"**{row['vendor_name']}** ({row['cve_count']} CVEs)")
        if col2.button("↻", key=f"update_{row['vendor_id']}", help="Update"):
            build_vendor_data(row['vendor_id'], row['vendor_name'], update_only=True)
            st.rerun()
else:
    st.sidebar.info("No companies fetched yet. Add one below!")

st.sidebar.divider()

# Add new vendor
st.sidebar.subheader("Add New Company")

if vendors:
    vendor_names = [v["name"] for v in vendors]
    selected_vendor_name = st.sidebar.selectbox(
        "Select Vendor",
        options=[""] + vendor_names,
        help="Search for any vendor from CVEDetails.com"
    )
    
    if selected_vendor_name:
        selected_vendor = next((v for v in vendors if v["name"] == selected_vendor_name), None)
        
        if selected_vendor:
            vendor_id = selected_vendor["id"]
            
            # Check if already fetched
            already_fetched = vendor_id in fetched_vendors_df['vendor_id'].values if not fetched_vendors_df.empty else False
            
            if already_fetched:
                st.sidebar.warning(f"{selected_vendor_name} already in database.")
            else:
                if st.sidebar.button(f"🔨 Build {selected_vendor_name}", type="primary"):
                    build_vendor_data(vendor_id, selected_vendor_name)
                    st.rerun()
else:
    st.sidebar.warning("Vendor list not loaded. Click below to fetch.")
    if st.sidebar.button("📥 Fetch Vendor List"):
        with st.spinner("Fetching vendors A-Z (this takes a few minutes)..."):
            scraper = VendorScraper(headless=True)
            scraper.get_all_vendors(force_refresh=True)
        st.cache_data.clear()
        st.rerun()

# --- Main Dashboard ---
if fetched_vendors_df.empty:
    st.info("👋 Welcome! Select a company from the sidebar and click **Build** to get started.")
    st.stop()

# Vendor selector for dashboard
st.sidebar.divider()
st.sidebar.subheader("📈 View Dashboard")
dashboard_vendor = st.sidebar.selectbox(
    "Select Company to View",
    options=fetched_vendors_df['vendor_name'].tolist(),
    key="dashboard_vendor"
)

# Get vendor ID
vendor_row = fetched_vendors_df[fetched_vendors_df['vendor_name'] == dashboard_vendor].iloc[0]
current_vendor_id = vendor_row['vendor_id']

# Load data for selected vendor
@st.cache_data
def load_vendor_data(vendor_id):
    storage = get_storage()
    df = storage.get_cves_by_vendor(vendor_id)
    products = storage.con.execute("""
        SELECT * FROM products WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)
    """, (vendor_id,)).fetchdf()
    cwes = storage.con.execute("""
        SELECT * FROM weaknesses WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)
    """, (vendor_id,)).fetchdf()
    return df, products, cwes

try:
    df_cves, df_products, df_cwes = load_vendor_data(current_vendor_id)
except Exception as e:
    st.error(f"Error loading data: {e}")
    st.stop()

if df_cves.empty:
    st.warning(f"No CVE data found for {dashboard_vendor}. Try updating.")
    st.stop()

# --- Filters ---
st.sidebar.divider()
st.sidebar.header("🔍 Filters")

# Date Range
min_date = pd.to_datetime(df_cves['published_date']).min()
max_date = pd.to_datetime(df_cves['published_date']).max()
if pd.isnull(min_date): min_date = datetime(2000,1,1)
if pd.isnull(max_date): max_date = datetime.now()

date_range = st.sidebar.date_input("Date Range", value=(min_date, max_date))

# Severity
severities = df_cves['cvss_v31_severity'].dropna().unique().tolist()
selected_severity = st.sidebar.multiselect("Severity", severities, default=severities)

# Apply filters
mask = (pd.to_datetime(df_cves['published_date']) >= pd.to_datetime(date_range[0])) & \
       (pd.to_datetime(df_cves['published_date']) <= pd.to_datetime(date_range[1]))
filtered_df = df_cves[mask]

if selected_severity:
    filtered_df = filtered_df[filtered_df['cvss_v31_severity'].isin(selected_severity)]

# --- KPIs ---
st.header(f"📊 {dashboard_vendor} Security Overview")

# Row 1
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total CVEs", len(filtered_df))

avg_score = filtered_df['cvss_v31_base_score'].mean()
col2.metric("Avg CVSS", f"{avg_score:.1f}" if not pd.isna(avg_score) else "N/A")

critical_count = len(filtered_df[filtered_df['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])])
col3.metric("Critical/High", critical_count)

ninety_days_ago = datetime.now() - timedelta(days=90)
recent = len(filtered_df[pd.to_datetime(filtered_df['published_date']) >= ninety_days_ago])
col4.metric("Last 90 Days", recent)

products_count = df_products['product'].nunique()
col5.metric("Products", products_count)

# Row 2
col6, col7, col8, col9, col10 = st.columns(5)
cwe_count = df_cwes['cwe_id'].nunique()
col6.metric("Unique CWEs", cwe_count)

max_score = filtered_df['cvss_v31_base_score'].max()
col7.metric("Max Score", f"{max_score:.1f}" if not pd.isna(max_score) else "N/A")

if not filtered_df.empty:
    filtered_df = filtered_df.copy()
    filtered_df['published_date'] = pd.to_datetime(filtered_df['published_date'])
    filtered_df['year'] = filtered_df['published_date'].dt.year
    year_range = f"{filtered_df['year'].min()}-{filtered_df['year'].max()}"
else:
    year_range = "N/A"
col8.metric("Year Range", year_range)

low_count = len(filtered_df[filtered_df['cvss_v31_severity'].isin(['LOW', 'MEDIUM'])])
col9.metric("Low/Medium", low_count)

# Top CWE
if not df_cwes.empty:
    top_cwe = df_cwes['cwe_id'].value_counts().head(1)
    col10.metric("Top CWE", top_cwe.index[0] if len(top_cwe) > 0 else "N/A")
else:
    col10.metric("Top CWE", "N/A")

# --- Vulnerability Classification ---
def classify_vuln(row):
    desc = str(row.get('description_en', '')).lower()
    cwe_list = df_cwes[df_cwes['cve_id'] == row['cve_id']]['cwe_id'].tolist()
    cwes = ' '.join(cwe_list)
    
    if 'CWE-89' in cwes or 'sql injection' in desc: return 'SQL Injection'
    if 'CWE-79' in cwes or 'cross-site scripting' in desc or 'xss' in desc: return 'XSS'
    if any(c in cwes for c in ['CWE-78', 'CWE-77', 'CWE-94']) or 'code execution' in desc or 'command injection' in desc: return 'Code Execution'
    if any(c in cwes for c in ['CWE-119', 'CWE-120', 'CWE-787', 'CWE-416']) or 'overflow' in desc or 'memory' in desc: return 'Memory/Overflow'
    if 'CWE-22' in cwes or 'traversal' in desc or 'path' in desc: return 'Path Traversal'
    if 'CWE-287' in cwes or 'CWE-269' in cwes or 'authentication' in desc or 'privilege' in desc: return 'Auth/Privilege'
    if 'CWE-200' in cwes or 'information disclosure' in desc or 'sensitive' in desc: return 'Info Disclosure'
    if 'CWE-352' in cwes or 'csrf' in desc: return 'CSRF'
    if 'CWE-611' in cwes or 'xxe' in desc: return 'XXE'
    if 'CWE-502' in cwes or 'deserialization' in desc: return 'Deserialization'
    return 'Other'

if not filtered_df.empty:
    filtered_df['vuln_type'] = filtered_df.apply(classify_vuln, axis=1)
    
    # OWASP Mapping
    owasp_map = {
        'SQL Injection': 'A03:2021 - Injection',
        'XSS': 'A03:2021 - Injection',
        'Code Execution': 'A03:2021 - Injection',
        'Path Traversal': 'A01:2021 - Broken Access Control',
        'Auth/Privilege': 'A01:2021 - Broken Access Control',
        'Info Disclosure': 'A02:2021 - Cryptographic Failures',
        'CSRF': 'A01:2021 - Broken Access Control',
        'XXE': 'A05:2021 - Security Misconfiguration',
        'Deserialization': 'A08:2021 - Integrity Failures',
        'Memory/Overflow': 'A06:2021 - Vulnerable Components',
        'Other': 'Other'
    }
    filtered_df['owasp_category'] = filtered_df['vuln_type'].map(owasp_map)

# --- Charts ---
st.subheader("📈 Trends & Distribution")
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Timeline", "Severity", "Products", "CWEs", "OWASP", "Vuln Types"])

with tab1:
    if not filtered_df.empty:
        ts_df = filtered_df.set_index('published_date').resample('ME').size().reset_index(name='count')
        fig = px.bar(ts_df, x='published_date', y='count', title="CVEs Published Over Time",
                     color_discrete_sequence=['#1f77b4'])
        st.plotly_chart(fig, use_container_width=True)
        
        # Yearly trend
        yearly = filtered_df.groupby('year').size().reset_index(name='count')
        fig2 = px.line(yearly, x='year', y='count', title="Yearly Trend", markers=True)
        st.plotly_chart(fig2, use_container_width=True)

with tab2:
    if not filtered_df.empty:
        col_a, col_b = st.columns(2)
        with col_a:
            sev_counts = filtered_df['cvss_v31_severity'].value_counts().reset_index()
            colors = {'CRITICAL': '#d62728', 'HIGH': '#ff7f0e', 'MEDIUM': '#ffbb78', 'LOW': '#2ca02c'}
            fig = px.pie(sev_counts, values='count', names='cvss_v31_severity', 
                        title="Severity Distribution", hole=0.4,
                        color='cvss_v31_severity', color_discrete_map=colors)
            st.plotly_chart(fig, use_container_width=True)
        
        with col_b:
            # Severity over time
            sev_time = filtered_df.groupby([filtered_df['year'], 'cvss_v31_severity']).size().reset_index(name='count')
            fig = px.bar(sev_time, x='year', y='count', color='cvss_v31_severity',
                        title="Severity by Year", barmode='stack',
                        color_discrete_map=colors)
            st.plotly_chart(fig, use_container_width=True)

with tab3:
    if not df_products.empty:
        current_cves = filtered_df['cve_id'].unique()
        current_products = df_products[df_products['cve_id'].isin(current_cves)]
        top_prods = current_products['product'].value_counts().head(10).reset_index()
        fig = px.bar(top_prods, x='count', y='product', title="Top 10 Affected Products", 
                     orientation='h', color='count', color_continuous_scale='Blues')
        fig.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig, use_container_width=True)

with tab4:
    if not df_cwes.empty:
        current_cves = filtered_df['cve_id'].unique()
        current_cwes = df_cwes[df_cwes['cve_id'].isin(current_cves)]
        top_cwes = current_cwes['cwe_id'].value_counts().head(10).reset_index()
        
        col_a, col_b = st.columns(2)
        with col_a:
            fig = px.bar(top_cwes, x='count', y='cwe_id', title="Top 10 CWE Weaknesses",
                        orientation='h', color='count', color_continuous_scale='Reds')
            fig.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
        
        with col_b:
            # CWE descriptions
            st.markdown("### CWE Reference")
            cwe_desc = {
                "CWE-79": "Cross-site Scripting (XSS)",
                "CWE-89": "SQL Injection",
                "CWE-22": "Path Traversal",
                "CWE-78": "OS Command Injection",
                "CWE-287": "Improper Authentication",
                "CWE-269": "Improper Privilege Management",
                "CWE-200": "Information Exposure",
                "CWE-352": "Cross-Site Request Forgery",
                "CWE-502": "Deserialization of Untrusted Data",
                "CWE-20": "Improper Input Validation",
                "CWE-94": "Code Injection",
                "CWE-119": "Buffer Overflow",
                "CWE-787": "Out-of-bounds Write",
            }
            for cwe in top_cwes['cwe_id'].head(8):
                desc = cwe_desc.get(cwe, "See MITRE CWE database")
                st.write(f"**{cwe}**: {desc}")
    else:
        st.info("No CWE data available")

with tab5:
    if not filtered_df.empty and 'owasp_category' in filtered_df.columns:
        owasp_counts = filtered_df['owasp_category'].value_counts().reset_index()
        
        col_a, col_b = st.columns(2)
        with col_a:
            fig = px.pie(owasp_counts, values='count', names='owasp_category',
                        title="OWASP Top 10 (2021) Distribution", hole=0.3)
            st.plotly_chart(fig, use_container_width=True)
        
        with col_b:
            fig = px.bar(owasp_counts, x='count', y='owasp_category', orientation='h',
                        title="OWASP Categories Breakdown", color='count',
                        color_continuous_scale='Oranges')
            fig.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Classification data not available")

with tab6:
    if not filtered_df.empty and 'vuln_type' in filtered_df.columns:
        type_counts = filtered_df['vuln_type'].value_counts().reset_index()
        
        col_a, col_b = st.columns(2)
        with col_a:
            fig = px.pie(type_counts, values='count', names='vuln_type',
                        title="Vulnerability Type Distribution", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
        
        with col_b:
            # Type vs Year heatmap
            type_year = filtered_df.groupby(['year', 'vuln_type']).size().reset_index(name='count')
            pivot = type_year.pivot(index='vuln_type', columns='year', values='count').fillna(0)
            fig = px.imshow(pivot, title="Vulnerability Types Over Years",
                           labels=dict(x="Year", y="Type", color="Count"),
                           aspect='auto', color_continuous_scale='RdYlGn_r')
            st.plotly_chart(fig, use_container_width=True)

# --- Critical CVEs Section ---
st.subheader("� Critical & High Severity")
critical_df = filtered_df[filtered_df['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])].sort_values(
    'cvss_v31_base_score', ascending=False
)

if not critical_df.empty:
    st.warning(f"**{len(critical_df)}** vulnerabilities require immediate attention!")
    display_cols = ['cve_id', 'cvss_v31_severity', 'cvss_v31_base_score', 'vuln_type', 'description_en']
    cols_available = [c for c in display_cols if c in critical_df.columns]
    st.dataframe(
        critical_df[cols_available].head(15),
        use_container_width=True,
        column_config={
            "cvss_v31_base_score": st.column_config.NumberColumn("Score", format="%.1f"),
            "description_en": st.column_config.TextColumn("Description", width="large")
        }
    )
else:
    st.success("No critical or high severity CVEs in current filter!")

# --- Data Table ---
st.subheader("📋 All Vulnerabilities")
display_cols = ['cve_id', 'published_date', 'cvss_v31_severity', 'cvss_v31_base_score', 'description_en']
if 'vuln_type' in filtered_df.columns:
    display_cols.insert(4, 'vuln_type')

st.dataframe(
    filtered_df[display_cols].sort_values('cvss_v31_base_score', ascending=False),
    use_container_width=True,
    column_config={
        "cve_id": st.column_config.TextColumn("CVE ID"),
        "published_date": st.column_config.DateColumn("Published"),
        "cvss_v31_base_score": st.column_config.NumberColumn("Score", format="%.1f"),
        "description_en": st.column_config.TextColumn("Description", width="large")
    }
)

# --- Export ---
csv_data = filtered_df.to_csv(index=False).encode('utf-8')
st.download_button("📥 Download CSV", csv_data, f"{dashboard_vendor.lower()}_cves.csv", "text/csv")

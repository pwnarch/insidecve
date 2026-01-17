import streamlit as st
import pandas as pd
import duckdb
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

st.set_page_config(page_title="SolarWinds CVE Dashboard", layout="wide")

# Connect to DB (ReadOnly)
@st.cache_resource
def get_connection():
    return duckdb.connect("solarwinds_cves.duckdb", read_only=True)

@st.cache_data
def load_data():
    conn = get_connection()
    # Load Flattened Data
    df = conn.execute("SELECT * FROM flat_cves").fetchdf()
    # Load Products for filtering
    products = conn.execute("SELECT * FROM products").fetchdf()
    # Load Weaknesses for filtering
    cwes = conn.execute("SELECT * FROM weaknesses").fetchdf()
    return df, products, cwes

try:
    df_cves, df_products, df_cwes = load_data()
except Exception as e:
    st.error(f"Could not load data. Run pipeline.py first. Error: {e}")
    st.stop()

# --- Sidebar Filters ---
st.sidebar.header("Filters")

# Date Range
min_date = df_cves['published_date'].min()
max_date = df_cves['published_date'].max()
if pd.isnull(min_date): min_date = datetime(2000,1,1)
if pd.isnull(max_date): max_date = datetime.now()

date_range = st.sidebar.date_input(
    "Published Date Range",
    value=(min_date, max_date)
)

# Severity
severities = df_cves['cvss_v31_severity'].dropna().unique().tolist()
selected_severity = st.sidebar.multiselect("Severity", severities, default=severities)

# Products
# Get list of unique product names
# df_products has vendor, product, version.
unique_products = sorted(df_products['product'].unique().tolist())
selected_products = st.sidebar.multiselect("Products", unique_products)

# CWE
unique_cwes = sorted(df_cwes['cwe_id'].unique().tolist())
selected_cwes = st.sidebar.multiselect("CWEs", unique_cwes)

# Keyword
keyword = st.sidebar.text_input("Search (ID or Description)")

# --- Filter Logic ---
# 1. Filter by Date
mask = (df_cves['published_date'] >= pd.to_datetime(date_range[0])) & \
       (df_cves['published_date'] <= pd.to_datetime(date_range[1]))
filtered_df = df_cves[mask]

# 2. Filter by Severity
if selected_severity:
    filtered_df = filtered_df[filtered_df['cvss_v31_severity'].isin(selected_severity)]

# 3. Filter by Product
if selected_products:
    # Get CVE IDs that map to selected products
    valid_cves = df_products[df_products['product'].isin(selected_products)]['cve_id'].unique()
    filtered_df = filtered_df[filtered_df['cve_id'].isin(valid_cves)]

# 4. Filter by CWE
if selected_cwes:
    valid_cves_cwe = df_cwes[df_cwes['cwe_id'].isin(selected_cwes)]['cve_id'].unique()
    filtered_df = filtered_df[filtered_df['cve_id'].isin(valid_cves_cwe)]

# 5. Filter by Keyword
if keyword:
    kw = keyword.lower()
    filtered_df = filtered_df[
        filtered_df['cve_id'].str.lower().contains(kw) |
        filtered_df['description_en'].str.lower().contains(kw)
    ]

# --- Main Dashboard ---
st.title("SolarWinds CVE Analysis")

# KPIs - Row 1
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total CVEs", len(filtered_df))

avg_score = filtered_df['cvss_v31_base_score'].mean()
col2.metric("Avg CVSS v3.1", f"{avg_score:.2f}" if not pd.isna(avg_score) else "N/A")

# Critical/High count
critical_count = len(filtered_df[filtered_df['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])])
col3.metric("Critical/High", critical_count)

# Last 90 days
ninety_days_ago = datetime.now() - timedelta(days=90)
recent_count = len(filtered_df[filtered_df['published_date'] >= ninety_days_ago])
col4.metric("Last 90 Days", recent_count)

# Top Product
current_cve_ids = filtered_df['cve_id'].unique()
current_products = df_products[df_products['cve_id'].isin(current_cve_ids)]
top_prod = current_products['product'].mode()
col5.metric("Top Product", top_prod[0] if not top_prod.empty else "N/A")

# KPIs - Row 2
col6, col7, col8, col9, col10 = st.columns(5)

# Total Products Affected
unique_affected = current_products['product'].nunique()
col6.metric("Products Affected", unique_affected)

# Unique CWEs
current_cwes = df_cwes[df_cwes['cve_id'].isin(current_cve_ids)]
unique_cwe_count = current_cwes['cwe_id'].nunique()
col7.metric("Unique CWEs", unique_cwe_count)

# Max CVSS Score
max_score = filtered_df['cvss_v31_base_score'].max()
col8.metric("Max CVSS Score", f"{max_score:.1f}" if not pd.isna(max_score) else "N/A")

# Year Range
if not filtered_df.empty:
    min_year = filtered_df['published_date'].dt.year.min()
    max_year = filtered_df['published_date'].dt.year.max()
    col9.metric("Year Range", f"{min_year}-{max_year}")
else:
    col9.metric("Year Range", "N/A")

# Average per Year
if not filtered_df.empty:
    years_span = max_year - min_year + 1 if max_year > min_year else 1
    avg_per_year = len(filtered_df) / years_span
    col10.metric("Avg/Year", f"{avg_per_year:.1f}")
else:
    col10.metric("Avg/Year", "N/A")

# Charts
st.subheader("Trends & Distribution")
tab1, tab2, tab3, tab4, tab5 = st.tabs(["Over Time", "Severity", "Top Products", "Top CWEs", "OWASP Mapping"])

# Prepare Time Series with Year extraction for Heatmap
if not filtered_df.empty:
    # Avoid SettingWithCopyWarning
    filtered_df = filtered_df.copy()
    filtered_df['published_date'] = pd.to_datetime(filtered_df['published_date'])
    filtered_df['year'] = filtered_df['published_date'].dt.year

# --- Classification Logic ---
def classify_vuln(row):
    desc = str(row.get('description_en', '')).lower()
    cwes = str(row.get('cwe_list', ''))
    
    # Priority-based matching
    if 'CWE-89' in cwes or 'sql injection' in desc: return 'SQL Injection'
    if 'CWE-79' in cwes or 'cross-site scripting' in desc or 'xss' in desc: return 'XSS'
    if any(c in cwes for c in ['CWE-78', 'CWE-77', 'CWE-94']) or 'code execution' in desc or 'command injection' in desc: return 'Code Execution'
    if any(c in cwes for c in ['CWE-119', 'CWE-120', 'CWE-122', 'CWE-787', 'CWE-416']) or 'overflow' in desc or 'memory' in desc: return 'Memory/Overflow'
    if 'CWE-22' in cwes or 'traversal' in desc: return 'Directory Traversal'
    if 'CWE-287' in cwes or 'CWE-269' in cwes or 'authentication' in desc or 'privilege' in desc: return 'Auth/Privilege'
    if 'CWE-200' in cwes or 'information disclosure' in desc: return 'Info Disclosure'
    if 'CWE-352' in cwes or 'csrf' in desc: return 'CSRF'
    if 'CWE-611' in cwes or 'xxe' in desc: return 'XXE'
    if 'CWE-502' in cwes or 'deserialization' in desc: return 'Deserialization'
    
    return 'Other'

filtered_df['vuln_type'] = filtered_df.apply(classify_vuln, axis=1)

with tab1:
    # Resample by month
    if not filtered_df.empty:
        ts_df = filtered_df.set_index('published_date').resample('ME').size().reset_index(name='count')
        fig_time = px.bar(ts_df, x='published_date', y='count', title="CVEs Published Over Time")
        st.plotly_chart(fig_time, use_container_width=True)
        
        # --- Heatmap: Year vs Type ---
        st.markdown("### Vulnerability Trends (Type vs Year)")
        heatmap_data = filtered_df.groupby(['year', 'vuln_type']).size().reset_index(name='count')
        if not heatmap_data.empty:
            # Pivot for Heatmap format
            heatmap_pivot = heatmap_data.pivot(index='vuln_type', columns='year', values='count').fillna(0)
            fig_heat = px.imshow(
                heatmap_pivot,
                labels=dict(x="Year", y="Type", color="Count"),
                title="Vulnerability Type Intensity Map",
                aspect="auto",
                color_continuous_scale="Reds"
            )
            fig_heat.update_xaxes(side="top")
            st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No data for timeline.")

with tab2:
    if not filtered_df.empty:
        sev_counts = filtered_df['cvss_v31_severity'].value_counts().reset_index()
        # Fix: use 'hole' instead of 'donut'
        fig_sev = px.pie(sev_counts, values='count', names='cvss_v31_severity', title="Severity Distribution", hole=0.4)
        st.plotly_chart(fig_sev, use_container_width=True)

with tab3:
    if not current_products.empty:
        top_prods = current_products['product'].value_counts().head(10).reset_index()
        fig_prod = px.bar(top_prods, x='count', y='product', title="Top 10 Affected Products", orientation='h')
        # Fix: Sort bars
        fig_prod.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_prod, use_container_width=True)

with tab4:
    # Top 10 CWEs
    if not current_cwes.empty:
        top_cwes = current_cwes['cwe_id'].value_counts().head(10).reset_index()
        fig_cwe = px.bar(top_cwes, x='count', y='cwe_id', title="Top 10 CWE Types", orientation='h',
                         color='count', color_continuous_scale='Blues')
        fig_cwe.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_cwe, use_container_width=True)
        
        # CWE Description helper
        st.markdown("### Common CWE References")
        cwe_descriptions = {
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-22": "Path Traversal",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-20": "Improper Input Validation",
            "CWE-78": "OS Command Injection",
            "CWE-287": "Improper Authentication",
            "CWE-269": "Improper Privilege Management",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "XML External Entity (XXE)",
            "CWE-94": "Code Injection",
            "CWE-200": "Information Exposure",
            "CWE-119": "Buffer Overflow",
            "CWE-787": "Out-of-bounds Write",
            "CWE-416": "Use After Free",
        }
        for cwe_id in top_cwes['cwe_id'].head(5):
            desc = cwe_descriptions.get(cwe_id, "See MITRE CWE database")
            st.write(f"**{cwe_id}**: {desc}")
    else:
        st.info("No CWE data available.")

with tab5:
    # OWASP Top 10 Mapping
    st.markdown("### OWASP Top 10 (2021) Mapping")
    
    # Map vulnerability types to OWASP categories
    owasp_mapping = {
        'SQL Injection': 'A03:2021 - Injection',
        'Code Execution': 'A03:2021 - Injection',
        'XSS': 'A03:2021 - Injection',
        'Directory Traversal': 'A01:2021 - Broken Access Control',
        'Auth/Privilege': 'A01:2021 - Broken Access Control',
        'Info Disclosure': 'A02:2021 - Cryptographic Failures',
        'CSRF': 'A01:2021 - Broken Access Control',
        'XXE': 'A05:2021 - Security Misconfiguration',
        'Deserialization': 'A08:2021 - Software and Data Integrity Failures',
        'Memory/Overflow': 'A06:2021 - Vulnerable Components',
        'Other': 'Other/Unclassified'
    }
    
    if not filtered_df.empty and 'vuln_type' in filtered_df.columns:
        # Map to OWASP
        filtered_df['owasp_category'] = filtered_df['vuln_type'].map(owasp_mapping).fillna('Other/Unclassified')
        owasp_counts = filtered_df['owasp_category'].value_counts().reset_index()
        
        fig_owasp = px.pie(owasp_counts, values='count', names='owasp_category', 
                           title="Distribution by OWASP Top 10 (2021)", hole=0.4)
        st.plotly_chart(fig_owasp, use_container_width=True)
        
        # Breakdown table
        st.markdown("### Vulnerability Type to OWASP Mapping")
        type_owasp = filtered_df.groupby(['vuln_type', 'owasp_category']).size().reset_index(name='count')
        type_owasp = type_owasp.sort_values('count', ascending=False)
        st.dataframe(type_owasp, use_container_width=True)
    else:
        st.info("No classification data available.")

# --- Critical/High CVEs Section ---
st.subheader("🚨 Critical & High Severity CVEs")
critical_high_df = filtered_df[filtered_df['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])].sort_values(
    'cvss_v31_base_score', ascending=False
)

if not critical_high_df.empty:
    st.warning(f"**{len(critical_high_df)}** vulnerabilities require immediate attention!")
    
    # Show top 10 most critical
    st.markdown("#### Top 10 Most Severe")
    display_critical = critical_high_df.head(10)[['cve_id', 'cvss_v31_severity', 'cvss_v31_base_score', 'vuln_type', 'description_en']]
    st.dataframe(
        display_critical,
        use_container_width=True,
        column_config={
            "cve_id": st.column_config.TextColumn("CVE ID"),
            "cvss_v31_severity": st.column_config.TextColumn("Severity"),
            "cvss_v31_base_score": st.column_config.NumberColumn("Score", format="%.1f"),
            "vuln_type": st.column_config.TextColumn("Type"),
            "description_en": st.column_config.TextColumn("Description", width="large")
        }
    )
else:
    st.success("No Critical or High severity CVEs in the current filter.")

# Data Table
st.subheader("📋 All Vulnerabilities")
# Enhance table with more columns
display_cols = ['cve_id', 'published_date', 'cvss_v31_severity', 'cvss_v31_base_score', 'vuln_type', 'description_en', 'cwe_list', 'product_list']

# Format nicely
st.dataframe(
    filtered_df[display_cols],
    use_container_width=True,
    column_config={
        "cve_id": st.column_config.TextColumn("CVE ID", help="The CVE Identifier"),
        "published_date": st.column_config.DatetimeColumn("Published", format="D MMM YYYY"),
        "cvss_v31_base_score": st.column_config.NumberColumn("Score", format="%.1f"),
        "vuln_type": st.column_config.TextColumn("Type"),
        "product_list": st.column_config.ListColumn("Products"),
        "cwe_list": st.column_config.ListColumn("CWEs"),
        "description_en": st.column_config.TextColumn("Description", width="large")
    }
)

# Product View (Optional Detail)
st.subheader("Product Deep Dive")
prod_view = st.selectbox("Select a Product to View Details", [""] + unique_products)
if prod_view:
    prod_cve_ids = df_products[df_products['product'] == prod_view]['cve_id'].unique()
    prod_df = df_cves[df_cves['cve_id'].isin(prod_cve_ids)]
    st.write(f"Showing {len(prod_df)} CVEs for **{prod_view}**")
    st.dataframe(prod_df[['cve_id', 'published_date', 'cvss_v31_severity', 'description_en']])

# Export
csv_data = filtered_df.to_csv(index=False).encode('utf-8')
st.download_button("Download Filtered Data (CSV)", csv_data, "filtered_cves.csv", "text/csv")

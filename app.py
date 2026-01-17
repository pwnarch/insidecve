"""
CVE Dashboard
Professional vulnerability intelligence platform with modern UI.
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

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="CVE Dashboard", 
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS ---
def load_css():
    st.markdown("""
        <style>
        /* Global Font */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }
        
        /* Metric Card */
        div.metric-card {
            background-color: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            height: 100%;
        }
        
        div.metric-label {
            color: #64748B;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }
        
        div.metric-value {
            color: #1E293B;
            font-size: 2rem;
            font-weight: 700;
        }
        
        div.metric-delta {
            font-size: 0.875rem;
            margin-top: 4px;
        }
        
        .c-red { color: #EF4444; }
        .c-green { color: #10B981; }
        .c-blue { color: #3B82F6; }
        
        /* Chart Container */
        div.chart-container {
            background-color: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        /* Sidebar Polish */
        section[data-testid="stSidebar"] {
            background-color: #F8FAFC;
            border-right: 1px solid #E2E8F0;
        }
        
        /* Header Polish */
        h1, h2, h3 {
            color: #0F172A;
            font-weight: 700;
        }
        
        /* Table highlight */
        div[data-testid="stDataFrame"] {
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            overflow: hidden;
        }
        </style>
    """, unsafe_allow_html=True)

load_css()

# --- HELPER: Metric Card ---
def metric_card(label, value, delta=None, color="", help_text=None):
    delta_html = ""
    if delta:
        delta_color = "c-red" if "-" in delta else "c-green" # Default logic
        if color: delta_color = color # Override
        delta_html = f'<div class="metric-delta {delta_color}">{delta}</div>'
        
    html = f"""
    <div class="metric-card">
        <div class="metric-label" title="{help_text if help_text else ''}">{label}</div>
        <div class="metric-value">{value}</div>
        {delta_html}
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)

# --- Session State & Database ---
if 'building' not in st.session_state: st.session_state.building = False

@st.cache_resource
def get_storage():
    return Storage(db_path="cve_dashboard.duckdb")

@st.cache_data(ttl=3600)
def load_vendor_list():
    vendors = get_cached_vendors()
    return vendors if vendors else []

# --- Logic: Build Data ---
def build_vendor_data(vendor_id: str, vendor_name: str, update_only: bool = False):
    storage = get_storage()
    existing_cves = set()
    if update_only:
        existing_cves = storage.get_existing_cve_ids(vendor_id)
        st.toast(f"Checking updates for {vendor_name} ({len(existing_cves)} existing)...")
    
    with st.spinner(f"Finding CVEs for {vendor_name}..."):
        scraper = VendorScraper(headless=True)
        cve_mapping = scraper.get_vendor_cves(vendor_id, vendor_name)
    
    if not cve_mapping:
        st.error("No CVEs found.")
        return

    cve_ids = list(cve_mapping.keys())
    if update_only:
        cve_ids = [c for c in cve_ids if c not in existing_cves]
        if not cve_ids:
            st.success("Up to date!")
            return
    
    with st.spinner(f"Fetching details for {len(cve_ids)} CVEs..."):
        fetcher = CVEDetailsFetcher(headless=True)
        details = fetcher.fetch_cve_details(cve_ids)
    
    with st.spinner("Saving..."):
        product_count = len(set(p for prods in cve_mapping.values() for p in prods))
        for cve_id, data in details.items():
            if "error" in data: continue
            record = {
                "cve_id": cve_id, "vendor_id": vendor_id,
                "published_date": data.get("published_date"),
                "last_modified_date": data.get("last_modified"),
                "description_en": data.get("description"),
                "source_flags": "cvedetails",
                "cvss_v31_base_score": data.get("cvss_v31_base_score"),
                "cvss_v31_severity": data.get("cvss_v31_severity"),
                "cvss_v31_vector": data.get("cvss_vector"),
                "cvss_v4_base_score": None, "cvss_v4_severity": None, "cvss_v4_vector": None,
                "cwe_ids": data.get("cwe_id", ""),
                "reference_urls": ",".join(data.get("references", [])[:5]),
                "products": ""
            }
            storage.save_cve(record, vendor_id)
            if cve_id in cve_mapping:
                for prod in cve_mapping[cve_id]:
                    storage.add_product_mapping(cve_id, prod, vendor_name)
        
        total_cves = len(storage.get_existing_cve_ids(vendor_id))
        storage.update_vendor_metadata(vendor_id, vendor_name, total_cves, product_count)
    
    st.success(f"Updated {vendor_name}!")
    st.cache_data.clear()

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ CVE Watch")
    st.markdown("---")
    
    # 1. Select Vendor
    st.subheader("Dashboard")
    vendors = load_vendor_list()
    storage = get_storage()
    fetched_vendors_df = storage.get_fetched_vendors()
    
    selected_vendor_name = None
    if not fetched_vendors_df.empty:
        selected_vendor_name = st.selectbox(
            "Select Company",
            options=fetched_vendors_df['vendor_name'].tolist(),
            key="dashboard_vendor"
        )
        
        # Update Button
        row = fetched_vendors_df[fetched_vendors_df['vendor_name'] == selected_vendor_name].iloc[0]
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("↻", help="Update Data"):
                build_vendor_data(row['vendor_id'], row['vendor_name'], update_only=True)
                st.rerun()
        with col2:
            st.caption(f"Last updated: {pd.to_datetime(row['last_updated']).strftime('%Y-%m-%d')}")
    else:
        st.info("No data yet. Determine a vendor below.")

    st.markdown("---")
    
    # 2. Add New
    with st.expander("Add New Company"):
        if vendors:
            vendor_opts = [v["name"] for v in vendors]
            new_vendor = st.selectbox("Find Vendor", [""] + vendor_opts)
            if new_vendor:
                v_data = next((v for v in vendors if v["name"] == new_vendor), None)
                if st.button(f"Build {new_vendor}", type="primary", use_container_width=True):
                    build_vendor_data(v_data["id"], new_vendor)
                    st.rerun()
        else:
            if st.button("Fetch Vendor List (A-Z)"):
                with st.spinner("Fetching..."):
                    VendorScraper(headless=True).get_all_vendors(force_refresh=True)
                st.rerun()

    st.markdown("---")
    st.markdown("*v2.0 • [GitHub](https://github.com/pwnarch/insidecve)*")

# --- MAIN CONTENT ---
if not selected_vendor_name:
    st.title("Welcome to CVE Watch")
    st.markdown("""
    ### Getting Started
    1. Look for a company in the **Sidebar** > **Add New Company**
    2. Click **Build** to generate their security profile
    3. Analyze trends, severity, and critical vulnerabilities
    """)
    st.stop()

# Load Data
current_vendor_id = fetched_vendors_df[fetched_vendors_df['vendor_name'] == selected_vendor_name].iloc[0]['vendor_id']

@st.cache_data
def load_data(vid):
    s = get_storage()
    cves = s.get_cves_by_vendor(vid)
    prods = s.con.execute("SELECT * FROM products WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)", (vid,)).fetchdf()
    cwes = s.con.execute("SELECT * FROM weaknesses WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)", (vid,)).fetchdf()
    return cves, prods, cwes

try:
    df_cves, df_products, df_cwes = load_data(current_vendor_id)
except Exception as e:
    st.error(f"Data load error: {e}")
    st.stop()

# FILTERS
st.write("") # Spacer
c1, c2, c3 = st.columns([3, 1, 1])
with c1:
    st.title(f"{selected_vendor_name} Intelligence")
with c2:
    min_d = pd.to_datetime(df_cves['published_date']).min()
    max_d = pd.to_datetime(df_cves['published_date']).max()
    if pd.isnull(min_d): min_d = datetime(2000,1,1)
    if pd.isnull(max_d): max_d = datetime.now()
    dates = st.date_input("Filter Date", [min_d, max_d])

# Apply Filter
mask = (pd.to_datetime(df_cves['published_date']) >= pd.to_datetime(dates[0])) & \
       (pd.to_datetime(df_cves['published_date']) <= pd.to_datetime(dates[1]))
fdf = df_cves[mask]

# --- KPI ROW ---
col1, col2, col3, col4 = st.columns(4)

with col1:
    metric_card("Total CVEs", len(fdf), f"+{len(fdf[pd.to_datetime(fdf['published_date']) > datetime.now()-timedelta(days=30)])} this month")

with col2:
    crit = len(fdf[fdf['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])])
    pct = (crit/len(fdf)*100) if len(fdf) > 0 else 0
    metric_card("Critical & High", crit, f"{pct:.1f}% of total", "c-red")

with col3:
    avg = fdf['cvss_v31_base_score'].mean()
    metric_card("Avg CVSS Score", f"{avg:.1f}", "Base Score v3.1", "c-blue")

with col4:
    prods = df_products[df_products['cve_id'].isin(fdf['cve_id'])]['product'].nunique()
    metric_card("Impacted Products", prods, "Total Unique")

# --- CHARTS ---
st.write("")
tabs = st.tabs(["📊 Analytics", "📋 Vulnerabilities", "🚨 Critical List"])

with tabs[0]:
    # Row 1: Timeline & Severity
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.subheader("Vulnerability Timeline")
        fdf['published_date'] = pd.to_datetime(fdf['published_date'])
        ts = fdf.set_index('published_date').resample('M').size().reset_index(name='count')
        fig = px.bar(ts, x='published_date', y='count', color_discrete_sequence=['#3B82F6'])
        fig.update_layout(xaxis_title="", yaxis_title="New CVEs", showlegend=False, margin=dict(l=0,r=0,t=0,b=0), height=300)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with c2:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.subheader("Severity Breakdown")
        sev = fdf['cvss_v31_severity'].value_counts()
        colors = {'CRITICAL': '#EF4444', 'HIGH': '#F97316', 'MEDIUM': '#F59E0B', 'LOW': '#10B981'}
        fig = px.donut(values=sev.values, names=sev.index, color=sev.index, color_discrete_map=colors, hole=0.6)
        fig.update_layout(showlegend=False, margin=dict(l=0,r=0,t=0,b=0), height=300)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Row 2: Heatmap & Products
    c1, c2 = st.columns(2)
    with c1:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.subheader("Top Weaknesses (CWE)")
        if not df_cwes.empty:
            cwes = df_cwes[df_cwes['cve_id'].isin(fdf['cve_id'])]['cwe_id'].value_counts().head(8)
            fig = px.bar(x=cwes.values, y=cwes.index, orientation='h', color=cwes.values, color_continuous_scale='Reds')
            fig.update_layout(yaxis={'categoryorder':'total ascending'}, xaxis_title="Count", yaxis_title="", margin=dict(l=0,r=0,t=0,b=0), height=300, coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)
        else: st.info("No CWE data")
        st.markdown('</div>', unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.subheader("Most Affected Products")
        if not df_products.empty:
            prods = df_products[df_products['cve_id'].isin(fdf['cve_id'])]['product'].value_counts().head(8)
            fig = px.bar(x=prods.values, y=prods.index, orientation='h', color=prods.values, color_continuous_scale='Blues')
            fig.update_layout(yaxis={'categoryorder':'total ascending'}, xaxis_title="Count", yaxis_title="", margin=dict(l=0,r=0,t=0,b=0), height=300, coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)
        else: st.info("No product data")
        st.markdown('</div>', unsafe_allow_html=True)

with tabs[1]:
    st.subheader("Full Vulnerability List")
    cols = ['cve_id', 'published_date', 'cvss_v31_severity', 'cvss_v31_base_score', 'description_en']
    st.dataframe(
        fdf[cols].sort_values('published_date', ascending=False),
        use_container_width=True,
        column_config={
            "cve_id": "ID",
            "published_date": st.column_config.DateColumn("Published"),
            "cvss_v31_severity": "Severity",
            "cvss_v31_base_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "description_en": st.column_config.TextColumn("Description", width="large")
        },
        height=600
    )

with tabs[2]:
    st.subheader("🚨 Priority Action List")
    crit = fdf[fdf['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])].sort_values('cvss_v31_base_score', ascending=False)
    if not crit.empty:
        for idx, row in crit.head(10).iterrows():
            with st.container():
                c1, c2 = st.columns([1, 10])
                with c1:
                    score = row['cvss_v31_base_score']
                    color = "#EF4444" if score >= 9.0 else "#F97316"
                    st.markdown(f"""
                    <div style="background-color:{color}; color:white; padding:10px; border-radius:5px; text-align:center; font-weight:bold;">
                        {score}
                    </div>
                    """, unsafe_allow_html=True)
                with c2:
                    st.markdown(f"**{row['cve_id']}** • {row['published_date'].strftime('%Y-%m-%d')}")
                    st.caption(row['description_en'])
                st.divider()
    else:
        st.success("No critical vulnerabilities found!")

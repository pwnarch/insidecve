"""
InsideCVE
Professional vulnerability intelligence platform.
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
    page_title="InsideCVE", 
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- CUSTOM CSS ---
def load_css():
    st.markdown("""
        <style>
        /* Global Font */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
            color: #111827;
        }
        
        /* Layout Grid */
        .bento-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 24px;
        }
        
        .bento-card {
            background-color: #FFFFFF;
            border: 1px solid #E5E7EB;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
            transition: all 0.2s;
        }
        
        .bento-card:hover {
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        /* Typography */
        h1 { font-weight: 700; font-size: 2.25rem; letter-spacing: -0.025em; color: #111827; }
        h2 { font-weight: 600; font-size: 1.5rem; letter-spacing: -0.025em; color: #1F2937; margin-bottom: 16px; }
        h3 { font-weight: 600; font-size: 1.125rem; color: #374151; }
        
        /* Metric Styling */
        .metric-label {
            font-size: 0.875rem;
            font-weight: 500;
            color: #6B7280;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .metric-value {
            font-size: 2.25rem;
            font-weight: 700;
            color: #111827;
            line-height: 1;
        }
        
        .metric-sub {
            font-size: 0.875rem;
            margin-top: 8px;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        
        /* Colors */
        .text-c-red { color: #DC2626; }
        .text-c-orange { color: #EA580C; }
        .text-c-green { color: #059669; }
        .text-c-blue { color: #2563EB; }
        
        /* Detail Page Headers */
        .detail-header-container {
            background-color: #F9FAFB;
            border-bottom: 1px solid #E5E7EB;
            padding: 32px 0;
            margin: -6rem -5rem 2rem -5rem;
            padding-left: 5rem;
            padding-right: 5rem;
        }
        
        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background-color: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; }
        .badge-high { background-color: #FFF7ED; color: #9A3412; border: 1px solid #FED7AA; }
        .badge-medium { background-color: #FFFBEB; color: #92400E; border: 1px solid #FDE68A; }
        .badge-low { background-color: #ECFDF5; color: #065F46; border: 1px solid #A7F3D0; }
        
        /* Links */
        a.cve-link {
            color: #2563EB;
            text-decoration: none;
            font-weight: 500;
        }
        a.cve-link:hover { text-decoration: underline; }
        
        /* Table Polish */
        div[data-testid="stDataFrame"] { border: none; }
        </style>
    """, unsafe_allow_html=True)

load_css()

# --- HELPER: Metric Card ---
def render_metric(label, value, sub_text=None, color_class="text-c-blue"):
    st.markdown(f"""
    <div class="bento-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-sub {color_class}">
            {sub_text if sub_text else '&nbsp;'}
        </div>
    </div>
    """, unsafe_allow_html=True)

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
        st.toast(f"Checking updates for {vendor_name}...")
    
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

# --- Logic: Classification ---
def classify_vuln(row, df_cwes):
    desc = str(row.get('description_en', '')).lower()
    cve_cwes = df_cwes[df_cwes['cve_id'] == row['cve_id']]['cwe_id'].tolist()
    cwes_str = ' '.join(cve_cwes)
    
    if 'CWE-89' in cwes_str or 'sql injection' in desc: return 'SQL Injection'
    if 'CWE-79' in cwes_str or 'xss' in desc: return 'XSS'
    if any(c in cwes_str for c in ['CWE-78', 'CWE-77']) or 'command injection' in desc: return 'RCE'
    if any(c in cwes_str for c in ['CWE-119', 'CWE-120', 'CWE-787']) or 'overflow' in desc: return 'Memory Corruption'
    if 'CWE-22' in cwes_str or 'traversal' in desc: return 'Path Traversal'
    if 'CWE-287' in cwes_str or 'authentication' in desc: return 'Auth Bypass'
    if 'CWE-200' in cwes_str or 'disclosure' in desc: return 'Info Leak'
    if 'CWE-352' in cwes_str or 'csrf' in desc: return 'CSRF'
    return 'Other'

# --- Logic: Render CVE Detail Page ---
def render_cve_detail(cve_id):
    storage = get_storage()
    cve_data = storage.con.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
    
    if not cve_data:
        st.error(f"CVE {cve_id} not found.")
        if st.button("← Back"): st.query_params.clear(); st.rerun()
        return

    cols = [d[0] for d in storage.con.description]
    cve = dict(zip(cols, cve_data))
    
    prods = storage.con.execute("SELECT product FROM products WHERE cve_id = ?", (cve_id,)).fetchall()
    prods_list = sorted(list(set(p[0] for p in prods)))
    
    cwes = storage.con.execute("SELECT cwe_id FROM weaknesses WHERE cve_id = ?", (cve_id,)).fetchall()
    cwes_list = [c[0] for c in cwes]
    
    references = storage.con.execute("SELECT url FROM cve_references WHERE cve_id = ?", (cve_id,)).fetchall()
    ref_list = [r[0] for r in references]

    # --- Header ---
    if st.button("← Back to Dashboard", type="secondary"):
        st.query_params.clear()
        st.rerun()
        
    sev = cve.get('cvss_v31_severity') or "UNKNOWN"
    score = cve.get('cvss_v31_base_score')
    badge_cls = f"badge-{sev.lower()}" if sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else "badge-low"
    
    st.markdown(f"""
    <div class="detail-header-container">
        <div style="font-size: 0.875rem; color: #6B7280; font-weight: 500; margin-bottom: 8px;">VULNERABILITY REPORT</div>
        <h1 style="margin: 0; font-size: 3rem;">{cve_id}</h1>
        <div style="display: flex; align-items: center; gap: 12px; margin-top: 16px;">
            <span class="badge {badge_cls}">{sev}</span>
            <span style="font-weight: 600; color: #374151;">CVSS {score}</span>
            <span style="color: #9CA3AF;">•</span>
            <span style="color: #6B7280;">Published {cve.get('published_date')}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # --- Content ---
    c1, c2 = st.columns([2, 1])
    
    with c1:
        st.markdown("### Description")
        st.write(cve.get('description_en') or "No description.")
        
        st.markdown("### Affected Products")
        if prods_list:
            if len(prods_list) > 15:
                st.write(", ".join(prods_list[:15]) + f" ... and {len(prods_list)-15} more")
                with st.expander("Show all"):
                    st.write(", ".join(prods_list))
            else:
                st.write(", ".join(prods_list))
        else:
            st.caption("No specific products listed.")

    with c2:
        st.markdown('<div class="bento-card">', unsafe_allow_html=True)
        st.markdown("### Technical Details")
        
        st.markdown("**CWE Weaknesses**")
        if cwes_list:
            for c in cwes_list:
                st.markdown(f"- [{c}](https://cwe.mitre.org/data/definitions/{c.split('-')[1]}.html)")
        else:
            st.caption("None")
            
        st.markdown("**CVSS Vector**")
        st.code(cve.get('cvss_v31_vector') or "N/A", language=None)
        
        st.markdown("**References**")
        with st.expander("View Links"):
             for r in ref_list: st.markdown(f"- [Link]({r})")
        st.markdown('</div>', unsafe_allow_html=True)

# --- CHECK ROUTING ---
if "cve" in st.query_params:
    render_cve_detail(st.query_params["cve"])
    st.stop()


# --- SIDEBAR ---
with st.sidebar:
    st.title("InsideCVE")
    
    vendors = load_vendor_list()
    storage = get_storage()
    fetched_vendors_df = storage.get_fetched_vendors()
    
    selected_vendor_name = None
    if not fetched_vendors_df.empty:
        selected_vendor_name = st.selectbox(
            "Company",
            options=fetched_vendors_df['vendor_name'].tolist(),
            key="dashboard_vendor"
        )
        row = fetched_vendors_df[fetched_vendors_df['vendor_name'] == selected_vendor_name].iloc[0]
        if st.button("Check for Updates", use_container_width=True):
            build_vendor_data(row['vendor_id'], row['vendor_name'], update_only=True)
            st.rerun()
        st.caption(f"Last sync: {pd.to_datetime(row['last_updated']).strftime('%Y-%m-%d')}")
    else:
        st.info("Select a vendor to start.")

    with st.expander("Add Vendor"):
        if vendors:
            vendor_opts = [v["name"] for v in vendors]
            new_v = st.selectbox("Search", [""] + vendor_opts)
            if new_v and st.button("Build Database"):
                v_data = next((v for v in vendors if v["name"] == new_v), None)
                build_vendor_data(v_data["id"], new_v)
                st.rerun()
        elif st.button("Load Vendor List"):
            VendorScraper(headless=True).get_all_vendors(force_refresh=True)
            st.rerun()
    
    st.divider()
    st.markdown("[GitHub Repo](https://github.com/pwnarch/insidecve)")

# --- MAIN DASHBOARD ---
if not selected_vendor_name:
    st.title("Welcome to InsideCVE")
    st.markdown("Select a company from the sidebar to view intelligence.")
    st.stop()

# Load Data
current_vendor_id = fetched_vendors_df[fetched_vendors_df['vendor_name'] == selected_vendor_name].iloc[0]['vendor_id']

@st.cache_data
def load_and_process(vid):
    s = get_storage()
    cves = s.get_cves_by_vendor(vid)
    prods = s.con.execute("SELECT * FROM products WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)", (vid,)).fetchdf()
    cwes = s.con.execute("SELECT * FROM weaknesses WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)", (vid,)).fetchdf()
    
    if not cves.empty:
        cves['published_date'] = pd.to_datetime(cves['published_date'])
        cves['vuln_type'] = cves.apply(lambda r: classify_vuln(r, cwes), axis=1)
        
    return cves, prods, cwes

try:
    df_cves, df_products, df_cwes = load_and_process(current_vendor_id)
except Exception as e:
    st.error(f"Error: {e}")
    st.stop()

# Header
st.title(selected_vendor_name)
st.markdown("Vulnerability Intelligence Dashboard")
st.write("")

# KPIs
col1, col2, col3, col4 = st.columns(4)
with col1:
    render_metric("Total CVEs", len(df_cves), "All time", "text-c-blue")
with col2:
    crit = len(df_cves[df_cves['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])])
    pct = (crit/len(df_cves)*100) if len(df_cves) > 0 else 0
    render_metric("Critical/High", crit, f"{pct:.0f}% of total", "text-c-red")
with col3:
    avg = df_cves['cvss_v31_base_score'].mean()
    render_metric("Avg Severity", f"{avg:.1f}", "CVSS v3.1", "text-c-orange")
with col4:
    cnt = df_products['product'].nunique()
    render_metric("Products", cnt, "Affected", "text-c-green")

# CHARTS
st.write("")
st.subheader("Analysis")

c1, c2 = st.columns([2, 1])
with c1:
    st.markdown('<div class="bento-card">', unsafe_allow_html=True)
    st.caption("VULNERABILITY TRENDS")
    ts = df_cves.set_index('published_date').resample('ME').size().reset_index(name='count')
    fig = px.bar(ts, x='published_date', y='count', color_discrete_sequence=['#2563EB'])
    fig.update_layout(height=280, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="")
    st.plotly_chart(fig, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with c2:
    st.markdown('<div class="bento-card">', unsafe_allow_html=True)
    st.caption("SEVERITY DISTRIBUTION")
    sev = df_cves['cvss_v31_severity'].value_counts()
    colors = {'CRITICAL':'#DC2626', 'HIGH':'#EA580C', 'MEDIUM':'#D97706', 'LOW':'#059669', 'UNKNOWN':'#9CA3AF'}
    fig = px.pie(values=sev.values, names=sev.index, color=sev.index, color_discrete_map=colors, hole=0.7)
    fig.update_layout(height=280, margin=dict(l=0,r=0,t=10,b=0), showlegend=False)
    fig.update_traces(textinfo='percent+label')
    st.plotly_chart(fig, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

c3, c4 = st.columns(2)
with c3:
    st.markdown('<div class="bento-card">', unsafe_allow_html=True)
    st.caption("TOP WEAKNESS TYPES (CWE)")
    if not df_cwes.empty:
        cwes = df_cwes[df_cwes['cve_id'].isin(df_cves['cve_id'])]['cwe_id'].value_counts().head(8)
        fig = px.bar(x=cwes.values, y=cwes.index, orientation='h', color=cwes.values, color_continuous_scale='Reds')
        fig.update_layout(height=250, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="", coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with c4:
    st.markdown('<div class="bento-card">', unsafe_allow_html=True)
    st.caption("VULNERABILITY CATEGORIES")
    vtypes = df_cves['vuln_type'].value_counts()
    fig = px.bar(x=vtypes.values, y=vtypes.index, orientation='h', color=vtypes.values, color_continuous_scale='Blues')
    fig.update_layout(height=250, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="", coloraxis_showscale=False)
    st.plotly_chart(fig, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# LIST
st.write("")
st.subheader("Vulnerabilities")
csv = df_cves.to_csv(index=False).encode('utf-8')
st.download_button("Download CSV", csv, "cve_data.csv", "text/csv")

# Custom Table
cols = ['cve_id', 'published_date', 'cvss_v31_severity', 'cvss_v31_base_score', 'description_en', 'vuln_type']
df_cves['LINK'] = df_cves['cve_id'].apply(lambda x: f"?cve={x}")

st.dataframe(
    df_cves[['LINK'] + cols].sort_values('published_date', ascending=False),
    use_container_width=True,
    column_config={
        "LINK": st.column_config.LinkColumn("", display_text="Open", width=60),
        "cve_id": st.column_config.TextColumn("ID", width=120),
        "published_date": st.column_config.DateColumn("Date", format="YYYY-MM-DD"),
        "cvss_v31_severity": "Severity",
        "cvss_v31_base_score": st.column_config.NumberColumn("Score", format="%.1f"),
        "description_en": st.column_config.TextColumn("Description", width="large"),
        "vuln_type": "Type"
    },
    height=800,
    hide_index=True
)

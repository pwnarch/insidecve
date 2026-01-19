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
from src.graph_visualizer import build_network_graph
from src.kev_checker import get_kev_checker


# --- PAGE CONFIG ---
st.set_page_config(
    page_title="InsideCVE", 
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS ---
def load_css():
    st.markdown("""
        <style>
        /* ═══════════════════════════════════════════════════════════════
           PREMIUM DARK THEME - Fashion Designer Quality
           Color Palette: Deep blacks, warm grays, muted accents
        ═══════════════════════════════════════════════════════════════ */
        
        /* Typography */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #E5E5E5;
            background-color: #0A0A0A;
        }
        
        /* Hide Streamlit Elements */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
        
        /* Main Container */
        .main {
            background-color: #0A0A0A;
        }
        
        .main .block-container {
            padding: 3rem 4rem;
            max-width: 1400px;
        }
        
        /* Premium Typography */
        h1 { 
            font-weight: 300; 
            font-size: 2.75rem; 
            letter-spacing: -0.03em;
            color: #FFFFFF;
            margin-bottom: 0.25rem;
        }
        
        h2 { 
            font-weight: 500; 
            font-size: 1.25rem; 
            letter-spacing: 0.02em;
            color: #A3A3A3;
            text-transform: uppercase;
            margin-bottom: 2rem;
        }
        
        h3 { 
            font-weight: 500; 
            font-size: 0.875rem;
            letter-spacing: 0.1em;
            color: #737373;
            text-transform: uppercase;
        }
        
        /* Subheader Styling */
        .stSubheader {
            color: #737373 !important;
        }

        /* ══════════════════════════════════════════════════════════════
           METRIC CARDS - Minimalist Dark Glass
        ══════════════════════════════════════════════════════════════ */
        .metric-card {
            background: linear-gradient(145deg, #141414 0%, #0D0D0D 100%);
            border: 1px solid #262626;
            border-radius: 16px;
            padding: 28px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
        }
        
        .metric-card:hover {
            border-color: #404040;
            transform: translateY(-4px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
        }
        
        .metric-card-accent {
            background: linear-gradient(145deg, #141414 0%, #0D0D0D 100%);
            border: 1px solid #8B5CF6;
            border-radius: 16px;
            padding: 28px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 0 30px rgba(139, 92, 246, 0.1);
        }
        
        .metric-card-accent:hover {
            box-shadow: 0 0 50px rgba(139, 92, 246, 0.2);
            transform: translateY(-4px);
        }
        
        .metric-card-critical {
            background: linear-gradient(145deg, #1A0A0A 0%, #0D0505 100%);
            border: 1px solid #7F1D1D;
            border-radius: 16px;
            padding: 28px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .metric-card-critical:hover {
            border-color: #991B1B;
            box-shadow: 0 0 40px rgba(127, 29, 29, 0.3);
            transform: translateY(-4px);
        }
        
        .metric-card-warning {
            background: linear-gradient(145deg, #1A1408 0%, #0D0A04 100%);
            border: 1px solid #78350F;
            border-radius: 16px;
            padding: 28px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .metric-card-warning:hover {
            border-color: #92400E;
            box-shadow: 0 0 40px rgba(120, 53, 15, 0.3);
            transform: translateY(-4px);
        }
        
        .metric-card-success {
            background: linear-gradient(145deg, #071A0F 0%, #040D08 100%);
            border: 1px solid #14532D;
            border-radius: 16px;
            padding: 28px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .metric-card-success:hover {
            border-color: #166534;
            box-shadow: 0 0 40px rgba(20, 83, 45, 0.3);
            transform: translateY(-4px);
        }
        
        .metric-label {
            font-size: 0.6875rem;
            font-weight: 500;
            color: #737373;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.15em;
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: 300;
            color: #FFFFFF;
            line-height: 1;
            letter-spacing: -0.02em;
        }
        
        .metric-sub {
            font-size: 0.75rem;
            margin-top: 16px;
            color: #525252;
            font-weight: 400;
            letter-spacing: 0.02em;
        }

        /* ══════════════════════════════════════════════════════════════
           FILTER CONTAINER - Dark Glass
        ══════════════════════════════════════════════════════════════ */
        div[data-testid="stExpander"] {
            background: #111111;
            border: 1px solid #262626;
            border-radius: 12px;
        }
        
        /* Container with border */
        div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlock"]:has(div[data-testid="stCheckbox"]) {
            background: #0F0F0F;
            border: 1px solid #1F1F1F;
            border-radius: 16px;
            padding: 24px;
        }

        /* ══════════════════════════════════════════════════════════════
           FORM ELEMENTS - Refined Dark
        ══════════════════════════════════════════════════════════════ */
        div[data-baseweb="select"] {
            background-color: #141414 !important;
            border-radius: 10px !important;
            border: 1px solid #262626 !important;
            transition: all 0.3s ease !important;
        }
        
        div[data-baseweb="select"]:hover {
            border-color: #404040 !important;
        }
        
        div[data-baseweb="select"]:focus-within {
            border-color: #8B5CF6 !important;
            box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2) !important;
        }
        
        /* Input fields */
        .stTextInput input, .stDateInput input {
            background-color: #141414 !important;
            border: 1px solid #262626 !important;
            border-radius: 10px !important;
            color: #E5E5E5 !important;
        }
        
        .stTextInput input:focus, .stDateInput input:focus {
            border-color: #8B5CF6 !important;
            box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2) !important;
        }

        /* ══════════════════════════════════════════════════════════════
           BUTTONS - Minimal Elegance
        ══════════════════════════════════════════════════════════════ */
        .stButton > button {
            background: transparent;
            border: 1px solid #404040;
            border-radius: 8px;
            color: #E5E5E5;
            font-weight: 500;
            font-size: 0.875rem;
            padding: 0.5rem 1.25rem;
            transition: all 0.3s ease;
            letter-spacing: 0.02em;
        }
        
        .stButton > button:hover {
            background: #1A1A1A;
            border-color: #8B5CF6;
            color: #FFFFFF;
        }
        
        .stButton > button[kind="primary"] {
            background: #8B5CF6;
            border: none;
            color: #FFFFFF;
        }
        
        .stButton > button[kind="primary"]:hover {
            background: #7C3AED;
            box-shadow: 0 8px 24px rgba(139, 92, 246, 0.3);
        }

        /* ══════════════════════════════════════════════════════════════
           SIDEBAR - Sleek Dark
        ══════════════════════════════════════════════════════════════ */
        section[data-testid="stSidebar"] {
            background-color: #0A0A0A;
            border-right: 1px solid #1A1A1A;
        }
        
        section[data-testid="stSidebar"] .stButton > button {
            width: 100%;
            justify-content: center;
        }

        /* ══════════════════════════════════════════════════════════════
           CHARTS & CONTAINERS
        ══════════════════════════════════════════════════════════════ */
        div[data-testid="stVerticalBlock"] > div:has(> div.stCaption) {
            background: #0F0F0F;
            border: 1px solid #1F1F1F;
            border-radius: 16px;
            padding: 24px;
            transition: all 0.3s ease;
        }
        
        div[data-testid="stVerticalBlock"] > div:has(> div.stCaption):hover {
            border-color: #2A2A2A;
        }
        
        .stCaption {
            font-weight: 500 !important;
            color: #525252 !important;
            font-size: 0.6875rem !important;
            text-transform: uppercase !important;
            letter-spacing: 0.15em !important;
        }

        /* ══════════════════════════════════════════════════════════════
           DATA TABLE - Dark Elegance
        ══════════════════════════════════════════════════════════════ */
        div[data-testid="stDataFrame"] {
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #1F1F1F;
        }
        
        div[data-testid="stDataFrame"] > div {
            background-color: #0F0F0F;
        }

        /* ══════════════════════════════════════════════════════════════
           BADGES - Refined
        ══════════════════════════════════════════════════════════════ */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }
        
        .badge-critical { 
            background: #7F1D1D;
            color: #FCA5A5;
        }
        .badge-high { 
            background: #78350F;
            color: #FCD34D;
        }
        .badge-medium { 
            background: #3F3F00;
            color: #FDE047;
        }
        .badge-low { 
            background: #14532D;
            color: #86EFAC;
        }
        .badge-kev {
            background: linear-gradient(135deg, #DC2626 0%, #991B1B 100%);
            color: #FFFFFF;
            border: 1px solid #FCA5A5;
            box-shadow: 0 0 20px rgba(220, 38, 38, 0.4);
            animation: pulse-kev 2s ease-in-out infinite;
        }
        
        @keyframes pulse-kev {
            0%, 100% { box-shadow: 0 0 20px rgba(220, 38, 38, 0.4); }
            50% { box-shadow: 0 0 30px rgba(220, 38, 38, 0.6); }
        }


        /* ══════════════════════════════════════════════════════════════
           DETAIL PAGE HEADER
        ══════════════════════════════════════════════════════════════ */
        .detail-header-container {
            background: linear-gradient(180deg, #141414 0%, #0A0A0A 100%);
            border-bottom: 1px solid #1F1F1F;
            padding: 48px 0;
            margin: -3rem -4rem 2rem -4rem;
            padding-left: 4rem;
            padding-right: 4rem;
        }
        
        .detail-header-container h1 {
            color: #FFFFFF;
        }

        /* ══════════════════════════════════════════════════════════════
           ANIMATIONS
        ══════════════════════════════════════════════════════════════ */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes glow {
            0%, 100% { box-shadow: 0 0 20px rgba(139, 92, 246, 0.1); }
            50% { box-shadow: 0 0 30px rgba(139, 92, 246, 0.2); }
        }
        
        /* Divider styling */
        hr {
            border: none;
            border-top: 1px solid #1F1F1F;
            margin: 2rem 0;
        }
        
        /* Link styling */
        a {
            color: #8B5CF6;
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        a:hover {
            color: #A78BFA;
        }
        
        /* Download button */
        .stDownloadButton > button {
            background: transparent;
            border: 1px solid #262626;
        }
        
        .stDownloadButton > button:hover {
            background: #141414;
            border-color: #404040;
        }
        
        /* Markdown text */
        .stMarkdown p {
            color: #A3A3A3;
        }
        </style>
    """, unsafe_allow_html=True)

load_css()

def render_metric(label, value, sub_text=None, card_class="metric-card"):
    st.markdown(f"""
    <div class="{card_class}">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-sub">
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
                "cwe_name": data.get("cwe_name", ""), # Added cwe_name
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

# --- Logic: OWASP Mapping ---
def get_owasp_category(vuln_type):
    mapping = {
        'SQL Injection': 'A03:2021-Injection',
        'RCE': 'A03:2021-Injection', # Often injection
        'XSS': 'A03:2021-Injection', # XSS is injection now
        'Auth Bypass': 'A07:2021-Identification and Authentication Failures',
        'Path Traversal': 'A01:2021-Broken Access Control',
        'CSRF': 'A04:2021-Insecure Design', # Broad categorization
        'Info Leak': 'A01:2021-Broken Access Control',
        'Memory Corruption': 'A02:2021-Cryptographic Failures' # Weak stretch, but fits 'software and data integrity' sometimes or memory safety
        # Better to map widely accepted CWE->OWASP 2021
    }
    return mapping.get(vuln_type, 'Uncategorized')

# --- CWE METADATA ---
CWE_METADATA = {
    'CWE-1021': {'name': 'Improper Restriction of Rendered UI Layers or Frames', 'category': 'Other'},
    'CWE-11': {'name': 'ASP.NET Misconfiguration: Creating Debug Binary', 'category': 'Other'},
    'CWE-116': {'name': 'Improper Encoding or Escaping of Output', 'category': 'Other'},
    'CWE-119': {'name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer', 'category': 'Memory'},
    'CWE-120': {'name': "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')", 'category': 'Memory'},
    'CWE-1236': {'name': 'Improper Neutralization of Formula Elements in a CSV File', 'category': 'Other'},
    'CWE-125': {'name': 'Out-of-bounds Read', 'category': 'Other'},
    'CWE-16': {'name': 'Configuration', 'category': 'Other'},
    'CWE-184': {'name': 'Incomplete List of Disallowed Inputs', 'category': 'Input Validation'},
    'CWE-20': {'name': 'Improper Input Validation', 'category': 'Input Validation'},
    'CWE-200': {'name': 'Exposure of Sensitive Information to an Unauthorized Actor', 'category': 'Access Control'},
    'CWE-209': {'name': 'Generation of Error Message Containing Sensitive Information', 'category': 'Other'},
    'CWE-22': {'name': "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", 'category': 'Other'},
    'CWE-255': {'name': 'Credentials Management', 'category': 'Other'},
    'CWE-264': {'name': 'Permissions, Privileges, and Access Controls', 'category': 'Access Control'},
    'CWE-269': {'name': 'Improper Privilege Management', 'category': 'Other'},
    'CWE-276': {'name': 'Incorrect Default Permissions', 'category': 'Other'},
    'CWE-284': {'name': 'Improper Access Control', 'category': 'Access Control'},
    'CWE-287': {'name': 'Improper Authentication', 'category': 'Access Control'},
    'CWE-288': {'name': 'Authentication Bypass Using an Alternate Path or Channel', 'category': 'Access Control'},
    'CWE-290': {'name': 'Authentication Bypass by Spoofing', 'category': 'Access Control'},
    'CWE-306': {'name': 'Missing Authentication for Critical Function', 'category': 'Access Control'},
    'CWE-310': {'name': 'Cryptographic Issues', 'category': 'Cryptography'},
    'CWE-311': {'name': 'Missing Encryption of Sensitive Data', 'category': 'Other'},
    'CWE-312': {'name': 'Cleartext Storage of Sensitive Information', 'category': 'Other'},
    'CWE-319': {'name': 'Cleartext Transmission of Sensitive Information', 'category': 'Other'},
    'CWE-321': {'name': 'Use of Hard-coded Cryptographic Key', 'category': 'Other'},
    'CWE-326': {'name': 'Inadequate Encryption Strength', 'category': 'Other'},
    'CWE-330': {'name': 'Use of Insufficiently Random Values', 'category': 'Other'},
    'CWE-331': {'name': 'Insufficient Entropy', 'category': 'Other'},
    'CWE-346': {'name': 'Origin Validation Error', 'category': 'Other'},
    'CWE-352': {'name': 'Cross-Site Request Forgery (CSRF)', 'category': 'Other'},
    'CWE-362': {'name': "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')", 'category': 'Other'},
    'CWE-384': {'name': 'Session Fixation', 'category': 'Other'},
    'CWE-399': {'name': 'Resource Management Errors', 'category': 'Resource'},
    'CWE-427': {'name': 'Uncontrolled Search Path Element', 'category': 'Other'},
    'CWE-428': {'name': 'Unquoted Search Path or Element', 'category': 'Other'},
    'CWE-434': {'name': 'Unrestricted Upload of File with Dangerous Type', 'category': 'Other'},
    'CWE-436': {'name': 'Interpretation Conflict', 'category': 'Other'},
    'CWE-444': {'name': "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')", 'category': 'Other'},
    'CWE-476': {'name': 'NULL Pointer Dereference', 'category': 'Other'},
    'CWE-502': {'name': 'Deserialization of Untrusted Data', 'category': 'Other'},
    'CWE-522': {'name': 'Insufficiently Protected Credentials', 'category': 'Other'},
    'CWE-532': {'name': 'Insertion of Sensitive Information into Log File', 'category': 'Other'},
    'CWE-601': {'name': "URL Redirection to Untrusted Site ('Open Redirect')", 'category': 'Other'},
    'CWE-611': {'name': 'Improper Restriction of XML External Entity Reference', 'category': 'Other'},
    'CWE-613': {'name': 'Insufficient Session Expiration', 'category': 'Other'},
    'CWE-614': {'name': "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", 'category': 'Other'},
    'CWE-639': {'name': 'Authorization Bypass Through User-Controlled Key', 'category': 'Access Control'},
    'CWE-650': {'name': 'Trusting HTTP Permission Methods on the Server Side', 'category': 'Other'},
    'CWE-696': {'name': 'Incorrect Behavior Order', 'category': 'Other'},
    'CWE-697': {'name': 'Incorrect Comparison', 'category': 'Other'},
    'CWE-732': {'name': 'Incorrect Permission Assignment for Critical Resource', 'category': 'Other'},
    'CWE-74': {'name': "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", 'category': 'Injection'},
    'CWE-749': {'name': 'Exposed Dangerous Method or Function', 'category': 'Other'},
    'CWE-755': {'name': 'Improper Handling of Exceptional Conditions', 'category': 'Other'},
    'CWE-77': {'name': "Improper Neutralization of Special Elements used in a Command ('Command Injection')", 'category': 'Injection'},
    'CWE-78': {'name': "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 'category': 'Injection'},
    'CWE-787': {'name': 'Out-of-bounds Write', 'category': 'Other'},
    'CWE-79': {'name': "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", 'category': 'Input Validation'},
    'CWE-798': {'name': 'Use of Hard-coded Credentials', 'category': 'Other'},
    'CWE-863': {'name': 'Incorrect Authorization', 'category': 'Access Control'},
    'CWE-89': {'name': "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", 'category': 'Injection'},
    'CWE-908': {'name': 'Use of Uninitialized Resource', 'category': 'Other'},
    'CWE-918': {'name': 'Server-Side Request Forgery (SSRF)', 'category': 'Other'},
    'CWE-94': {'name': "Improper Control of Generation of Code ('Code Injection')", 'category': 'Injection'},
}

def get_cwe_name(cwe_id):
    """Get human-readable name for a CWE ID."""
    return CWE_METADATA.get(cwe_id, {}).get('name', cwe_id)

def get_cwe_category(cwe_id):
    """Get category for a CWE ID."""
    return CWE_METADATA.get(cwe_id, {}).get('category', 'Other')

# --- Logic: Render CWE Analysis Page ---
def render_cwe_analysis(df_cves, df_cwes, vendor_name):
    """Render dedicated CWE analysis page with rich visualizations."""
    
    # Check for specific CWE drill-down
    focus_cwe = st.query_params.get("id")
    
    if st.button("← Back to Dashboard", type="secondary"):
        st.query_params.clear()
        st.rerun()

    if focus_cwe:
        # --- SINGLE CWE VIEW ---
        cwe_name = get_cwe_name(focus_cwe)
        cwe_cat = get_cwe_category(focus_cwe)
        
        st.title(f"{focus_cwe}: {cwe_name}")
        st.caption(f"Category: {cwe_cat}")
        
        # Filter Data
        related_cves = df_cwes[df_cwes['cwe_id'] == focus_cwe]['cve_id'].unique()
        df_filtered = df_cves[df_cves['cve_id'].isin(related_cves)]
        
        col1, col2, col3 = st.columns(3)
        with col1:
            render_metric("Total CVEs", len(df_filtered), f"With {focus_cwe}", "metric-card-accent")
        with col2:
            avg = df_filtered['cvss_v31_base_score'].mean() if not df_filtered.empty else 0
            render_metric("Avg Severity", f"{avg:.1f}", "CVSS Score", "metric-card-warning")
        with col3:
             crit = len(df_filtered[df_filtered['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])])
             render_metric("Critical/High", crit, "Vulnerabilities", "metric-card-critical")
             
        st.divider()
        st.subheader("Associated Vulnerabilities")
        
        if not df_filtered.empty:
            cols = ['cve_id', 'published_date', 'cvss_v31_severity', 'cvss_v31_base_score', 'description_en']
            # Create view df to avoid setting on slice
            view_df = df_filtered[cols].copy()
            view_df['LINK'] = view_df['cve_id'].apply(lambda x: f"?cve={x}")
            # Identify ID column URL
            view_df['cve_id'] = view_df['cve_id'].apply(lambda x: f"?cve={x}")
            
            st.dataframe(
                view_df[['LINK'] + cols].sort_values('published_date', ascending=False),
                use_container_width=True,
                column_config={
                    "LINK": st.column_config.LinkColumn("", display_text="Open", width=60),
                    "cve_id": st.column_config.LinkColumn("ID", display_text=r"\?cve=(.*)", width=120),
                    "published_date": st.column_config.DateColumn("Date", format="YYYY-MM-DD"),
                    "cvss_v31_severity": "Severity",
                    "cvss_v31_base_score": st.column_config.NumberColumn("Score", format="%.1f"),
                    "description_en": st.column_config.TextColumn("Description", width="large"),
                },
                hide_index=True
            )
        else:
            st.info("No vulnerabilities found for this CWE.")
            
        st.write("")
        st.markdown(f"**External Reference**: [MITRE {focus_cwe}](https://cwe.mitre.org/data/definitions/{focus_cwe.split('-')[1]}.html)")
        return

    # --- MAIN CWE DASHBOARD ---
    st.title("CWE Analysis")
    st.caption(f"WEAKNESS REPORT FOR {vendor_name.upper()}")
    
    if df_cwes.empty:
        st.warning("No CWE data available for this vendor.")
        return
    
    # Merge CWE with CVE data for analysis
    cwe_cve = df_cwes.merge(df_cves[['cve_id', 'cvss_v31_base_score', 'cvss_v31_severity', 'published_date']], on='cve_id', how='left')
    cwe_cve['cwe_name'] = cwe_cve['cwe_id'].apply(get_cwe_name)
    cwe_cve['cwe_category'] = cwe_cve['cwe_id'].apply(get_cwe_category)
    
    # --- KPI Cards ---
    st.write("")
    col1, col2, col3, col4 = st.columns(4)
    
    cwe_counts = cwe_cve['cwe_id'].value_counts()
    top_cwe = cwe_counts.index[0] if len(cwe_counts) > 0 else "N/A"
    top_cwe_name = get_cwe_name(top_cwe)
    
    cwe_severity = cwe_cve.groupby('cwe_id')['cvss_v31_base_score'].mean().sort_values(ascending=False)
    most_severe_cwe = cwe_severity.index[0] if len(cwe_severity) > 0 else "N/A"
    
    unique_cwes = cwe_cve['cwe_id'].nunique()
    unique_cats = cwe_cve['cwe_category'].nunique()
    
    with col1:
        render_metric("Unique CWEs", unique_cwes, "Distinct weaknesses", "metric-card-accent")
    with col2:
        render_metric("Most Common", top_cwe.split('-')[1] if '-' in str(top_cwe) else top_cwe, top_cwe_name[:20] + "..." if len(top_cwe_name) > 20 else top_cwe_name, "metric-card")
    with col3:
        render_metric("Categories", unique_cats, "Weakness types", "metric-card")
    with col4:
        avg_sev = cwe_cve['cvss_v31_base_score'].mean()
        render_metric("Avg Severity", f"{avg_sev:.1f}" if not pd.isna(avg_sev) else "N/A", "CVSS score", "metric-card-warning")
    
    # --- ROW 1: Treemap & Category Breakdown ---
    st.write("")
    c1, c2 = st.columns([2, 1])
    
    with c1:
        with st.container(border=True):
            st.caption("CWE RISK MATRIX")
            st.markdown("*Size = Frequency, Color = Avg Severity*")
            
            treemap_data = cwe_cve.groupby('cwe_id').agg({
                'cve_id': 'count',
                'cvss_v31_base_score': 'mean'
            }).reset_index()
            treemap_data.columns = ['CWE', 'Count', 'Avg_CVSS']
            treemap_data['Name'] = treemap_data['CWE'].apply(get_cwe_name)
            treemap_data['Category'] = treemap_data['CWE'].apply(get_cwe_category)
            treemap_data = treemap_data.nlargest(15, 'Count')
            
            if not treemap_data.empty:
                fig = px.treemap(
                    treemap_data,
                    path=['Category', 'CWE'],
                    values='Count',
                    color='Avg_CVSS',
                    color_continuous_scale=['#059669', '#D97706', '#DC2626'],
                    color_continuous_midpoint=6.5,
                    hover_data={'Name': True}
                )
                fig.update_layout(
                    height=350,
                    margin=dict(l=0, r=0, t=10, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#A3A3A3'
                )
                evt_tree = st.plotly_chart(fig, use_container_width=True, on_select="rerun", selection_mode="points", key="cwe_treemap")
                if evt_tree.selection and evt_tree.selection.points:
                    point = evt_tree.selection.points[0]
                    # Treemap hierarchy: Root -> Category -> CWE
                    # If clicked on CWE, the label/id should be the CWE ID
                    if 'label' in point:
                        sel_id = point['label']
                        if sel_id.startswith('CWE-'):
                            st.query_params['id'] = sel_id
                            st.rerun()
    
    with c2:
        with st.container(border=True):
            st.caption("CATEGORY BREAKDOWN")
            
            cat_counts = cwe_cve['cwe_category'].value_counts()
            if not cat_counts.empty:
                fig = px.pie(
                    values=cat_counts.values,
                    names=cat_counts.index,
                    hole=0.6,
                    color_discrete_sequence=['#8B5CF6', '#EC4899', '#F59E0B', '#10B981', '#3B82F6', '#6366F1']
                )
                fig.update_layout(
                    height=350,
                    margin=dict(l=0, r=0, t=10, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#A3A3A3',
                    showlegend=True,
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2)
                )
                fig.update_traces(textinfo='percent+label', textfont_size=10)
                st.plotly_chart(fig, use_container_width=True)
    
    # --- ROW 2: Severity Distribution & Trend ---
    c3, c4 = st.columns(2)
    
    with c3:
        with st.container(border=True):
            st.caption("SEVERITY DISTRIBUTION BY CWE")
            
            top_cwes = cwe_counts.head(8).index.tolist()
            box_data = cwe_cve[cwe_cve['cwe_id'].isin(top_cwes)]
            
            if not box_data.empty and box_data['cvss_v31_base_score'].notna().any():
                box_data = box_data.copy()
                box_data['cwe_name'] = box_data['cwe_id'].apply(get_cwe_name)
                fig = px.box(
                    box_data,
                    x='cwe_id',
                    y='cvss_v31_base_score',
                    color='cwe_id',
                    color_discrete_sequence=['#8B5CF6', '#EC4899', '#F59E0B', '#10B981', '#3B82F6', '#6366F1', '#EF4444', '#14B8A6'],
                    hover_data=['cwe_name']
                )
                fig.update_layout(
                    height=300,
                    margin=dict(l=0, r=0, t=10, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#A3A3A3',
                    xaxis_title="",
                    yaxis_title="CVSS Score",
                    showlegend=False
                )
                fig.update_xaxes(tickangle=45)
                fig.update_xaxes(tickangle=45)
                evt_box = st.plotly_chart(fig, use_container_width=True, on_select="rerun", selection_mode="points", key="cwe_box")
                if evt_box.selection and evt_box.selection.points:
                    point = evt_box.selection.points[0]
                    # x axis is CWE ID
                    sel_id = point.x
                    if sel_id and str(sel_id).startswith('CWE-'):
                        st.query_params['id'] = sel_id
                        st.rerun()
            else:
                st.info("Not enough severity data for visualization.")
    
    with c4:
        with st.container(border=True):
            st.caption("CWE TREND OVER TIME")
            
            if 'published_date' in cwe_cve.columns and cwe_cve['published_date'].notna().any():
                trend_data = cwe_cve.copy()
                trend_data['month'] = trend_data['published_date'].dt.to_period('M').astype(str)
                top_5_cwes = cwe_counts.head(5).index.tolist()
                trend_filtered = trend_data[trend_data['cwe_id'].isin(top_5_cwes)]
                
                if not trend_filtered.empty:
                    monthly = trend_filtered.groupby(['month', 'cwe_id']).size().reset_index(name='count')
                    monthly['cwe_name'] = monthly['cwe_id'].apply(get_cwe_name)
                    fig = px.line(
                        monthly,
                        x='month',
                        y='count',
                        color='cwe_id',
                        markers=True,
                        color_discrete_sequence=['#8B5CF6', '#EC4899', '#F59E0B', '#10B981', '#3B82F6'],
                        hover_data=['cwe_name']
                    )
                    fig.update_layout(
                        height=300,
                        margin=dict(l=0, r=0, t=10, b=0),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#A3A3A3',
                        xaxis_title="",
                        yaxis_title="Count",
                        legend=dict(orientation="h", yanchor="bottom", y=-0.3)
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("Not enough trend data.")
            else:
                st.info("No date data available for trends.")
    
    # --- ROW 3: Insights & Top CWEs List ---
    c5, c6 = st.columns([1, 2])
    
    with c5:
        with st.container(border=True):
            st.caption("KEY INSIGHTS")
            
            # Generate insights
            insights = []
            
            if len(cwe_counts) > 0:
                top_pct = (cwe_counts.iloc[0] / cwe_counts.sum()) * 100
                insights.append(f"**{top_cwe}** accounts for **{top_pct:.0f}%** of all weaknesses")
            
            injection_cats = cwe_cve[cwe_cve['cwe_category'] == 'Injection']
            if not injection_cats.empty:
                inj_pct = (len(injection_cats) / len(cwe_cve)) * 100
                insights.append(f"**Injection** vulnerabilities represent **{inj_pct:.0f}%** of issues")
            
            memory_cats = cwe_cve[cwe_cve['cwe_category'] == 'Memory']
            if not memory_cats.empty:
                mem_pct = (len(memory_cats) / len(cwe_cve)) * 100
                if mem_pct > 10:
                    insights.append(f"⚠️ **Memory safety** issues at **{mem_pct:.0f}%** - consider Rust/safe languages")
            
            high_sev = cwe_cve[cwe_cve['cvss_v31_base_score'] >= 9.0]
            if not high_sev.empty:
                critical_cwe = high_sev['cwe_id'].mode().iloc[0] if not high_sev['cwe_id'].mode().empty else None
                if critical_cwe:
                    insights.append(f"🔴 **{critical_cwe}** most linked to critical vulnerabilities")
            
            for insight in insights:
                st.markdown(f"• {insight}")
            
            if not insights:
                st.caption("Collect more CWE data for insights.")
    
    with c6:
        with st.container(border=True):
            st.caption("TOP 10 WEAKNESSES")
            
            top_10 = cwe_cve.groupby('cwe_id').agg({
                'cve_id': 'count',
                'cvss_v31_base_score': 'mean'
            }).reset_index()
            top_10.columns = ['CWE ID', 'CVE Count', 'Avg CVSS']
            top_10['Name'] = top_10['CWE ID'].apply(get_cwe_name)
            top_10['Category'] = top_10['CWE ID'].apply(get_cwe_category)
            top_10 = top_10.nlargest(10, 'CVE Count')
            top_10['Avg CVSS'] = top_10['Avg CVSS'].round(1)
            
            # Horizontal bar chart instead of table
            fig = px.bar(
                top_10,
                x='CVE Count',
                y='CWE ID',
                orientation='h',
                color='Avg CVSS',
                color_continuous_scale=['#059669', '#D97706', '#DC2626'],
                text='Name'
            )
            fig.update_layout(
                height=350,
                margin=dict(l=0, r=0, t=10, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#A3A3A3',
                xaxis_title="",
                yaxis_title="",
                coloraxis_showscale=False
            )
            fig.update_traces(textposition='inside', textfont_size=10)
            st.plotly_chart(fig, use_container_width=True)

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
                st.markdown(f"- [{c}](?page=cwe&id={c})")
        else:
            st.caption("None")
            
        st.markdown("**CVSS Vector**")
        st.code(cve.get('cvss_v31_vector') or "N/A", language=None)
        
        st.markdown("**References**")
        with st.expander("View Links"):
             for r in ref_list: st.markdown(f"- [Link]({r})")
        st.markdown('</div>', unsafe_allow_html=True)


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
    
    # Navigation Links
    if selected_vendor_name:
        st.caption("PAGES")
        if st.button("🏠 Dashboard", use_container_width=True, type="tertiary" if "page" not in st.query_params else "secondary"):
            st.query_params.clear()
            st.rerun()
        if st.button("🔬 CWE Analysis", use_container_width=True, type="tertiary" if st.query_params.get("page") != "cwe" else "secondary"):
            st.query_params["page"] = "cwe"
            st.rerun()
        if st.button("🕸️ Network Analysis", use_container_width=True, type="tertiary" if st.query_params.get("page") != "network" else "secondary"):
            st.query_params["page"] = "network"
            st.rerun()
    
    st.divider()
    st.markdown("[GitHub Repo](https://github.com/pwnarch/insidecve)")

# --- CHECK ROUTING ---
if "cve" in st.query_params:
    render_cve_detail(st.query_params["cve"])
    st.stop()


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
    
    # Update KEV status for all CVEs in database
    kev_checker = get_kev_checker()
    kev_cve_ids = kev_checker.get_all_kev_cves()
    if kev_cve_ids:
        updated_count = s.update_kev_status(kev_cve_ids)
        if updated_count > 0:
            st.toast(f"🚨 {updated_count} Known Exploited Vulnerabilities detected", icon="⚠️")
    
    cves = s.get_cves_by_vendor(vid)
    prods = s.con.execute("SELECT * FROM products WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)", (vid,)).fetchdf()
    cwes = s.con.execute("SELECT * FROM weaknesses WHERE cve_id IN (SELECT cve_id FROM cves WHERE vendor_id = ?)", (vid,)).fetchdf()
    
    if not cves.empty:
        cves['published_date'] = pd.to_datetime(cves['published_date'])
        
        # Merge CWEs into comma-separated string for table
        if not cwes.empty:
            cwe_joined = cwes.groupby('cve_id')['cwe_id'].apply(lambda x: ', '.join(x)).reset_index()
            cves = cves.merge(cwe_joined.rename(columns={'cwe_id': 'cwe_ids'}), on='cve_id', how='left')
        else:
            cves['cwe_ids'] = ""  

        cves['vuln_type'] = cves.apply(lambda r: classify_vuln(r, cwes), axis=1)
        cves['owasp'] = cves['vuln_type'].apply(get_owasp_category)
        
    return cves, prods, cwes

try:
    df_cves, df_products, df_cwes = load_and_process(current_vendor_id)
except Exception as e:
    st.error(f"Error: {e}")
    st.stop()

# --- FILTERS IN SIDEBAR ---
with st.sidebar:
    st.divider()
    st.subheader("Filters & Search")
    
    # Product search
    all_products = sorted(df_products['product'].dropna().unique())
    sel_products_top = st.multiselect("Products", all_products, default=[], key="product_search_top", placeholder="Filter by product...")
    
    st.write("")
    
    # Date Range
    min_d = df_cves['published_date'].min()
    max_d = df_cves['published_date'].max()
    if pd.isnull(min_d): min_d = datetime(2000,1,1)
    if pd.isnull(max_d): max_d = datetime.now()
    date_range = st.date_input("Date Range", [min_d, max_d])
    
    # Severity
    all_sev = sorted(df_cves['cvss_v31_severity'].dropna().unique())
    sel_sev = st.multiselect("Severity", all_sev, default=[], key="filter_severity")
    
    # Type
    all_types = sorted(df_cves['vuln_type'].unique())
    sel_types = st.multiselect("Vulnerability Type", all_types, default=[], key="filter_type")
    
    # CWE
    all_cwes = sorted(df_cwes['cwe_id'].unique())
    sel_cwes = st.multiselect("CWE ID", all_cwes, default=[], format_func=lambda x: f"{x} ({get_cwe_name(x)})", key="filter_cwe")
    
    st.divider()
    
    # Sort option
    sort_options = {
        "Published Date (Newest First)": ("published_date", False),
        "Published Date (Oldest First)": ("published_date", True),
        "CVSS Score (Highest First)": ("cvss_v31_base_score", False),
        "CVSS Score (Lowest First)": ("cvss_v31_base_score", True),
    }
    selected_sort_option = st.selectbox("Sort By", list(sort_options.keys()))
    sort_column, sort_ascending = sort_options[selected_sort_option]

# Apply Filters
if len(date_range) == 2:
    mask = (df_cves['published_date'] >= pd.to_datetime(date_range[0])) & \
           (df_cves['published_date'] <= pd.to_datetime(date_range[1]))
else:
    mask = pd.Series([True]*len(df_cves))

if sel_sev:
    mask &= df_cves['cvss_v31_severity'].isin(sel_sev)
if sel_types:
    mask &= df_cves['vuln_type'].isin(sel_types)
if sel_cwes:
    cve_ids_with_cwe = df_cwes[df_cwes['cwe_id'].isin(sel_cwes)]['cve_id'].unique()
    mask &= df_cves['cve_id'].isin(cve_ids_with_cwe)
if sel_products_top:
    matching_cve_ids = df_products[df_products['product'].isin(sel_products_top)]['cve_id'].unique()
    mask &= df_cves['cve_id'].isin(matching_cve_ids)
fdf = df_cves[mask]
if not fdf.empty:
    fdf = fdf.sort_values(sort_column, ascending=sort_ascending)

# --- CHECK CWE PAGE ROUTING ---
if st.query_params.get("page") == "cwe":
    render_cwe_analysis(fdf, df_cwes, selected_vendor_name)
    st.stop()

# --- CHECK NETWORK GRAPH ROUTING ---
if st.query_params.get("page") == "network":
    st.title("Attack Surface Graph")
    st.caption(f"VISUALIZING VULNERABILITY BLAST RADIUS FOR {selected_vendor_name}")
    
    # Legend / Instructions
    st.markdown("""
    <div style="display: flex; gap: 20px; margin-bottom: 20px; font-size: 0.8rem; color: #A3A3A3;">
        <span>⚪ Vendor</span>
        <span>🟣 Product (Size = Risk)</span>
        <span>🔴 Critical CVE</span>
        <span>🟠 High CVE</span>
    </div>
    """, unsafe_allow_html=True)
    
    with st.spinner("Calculating force-directed layout..."):
        # Use filtered data (fdf) so graph respects sidebar filters!
        fig = build_network_graph(fdf, df_products, selected_vendor_name)
        st.plotly_chart(fig, use_container_width=True, config={'scrollZoom': True})
    
    st.info("💡 Interaction: Zoom in to explore clusters. Hover over nodes for details.")
    st.stop()

# Header
st.title(selected_vendor_name)
st.caption("VULNERABILITY DASHBOARD")

st.write("")

# KPIs
st.write("")
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    render_metric("Total CVEs", len(fdf), "Selected range", "metric-card-accent")
with col2:
    kev_count = len(fdf[fdf.get('is_kev', False) == True]) if 'is_kev' in fdf.columns else 0
    render_metric("🚨 KEV", kev_count, "Actively exploited", "metric-card-critical")
with col3:
    crit = len(fdf[fdf['cvss_v31_severity'].isin(['CRITICAL', 'HIGH'])])
    pct = (crit/len(fdf)*100) if len(fdf) > 0 else 0
    render_metric("Critical / High", crit, f"{pct:.0f}% of selected", "metric-card-critical")
with col4:
    if not fdf.empty:
        avg = fdf['cvss_v31_base_score'].mean()
        render_metric("Avg Score", f"{avg:.1f}", "CVSS v3.1", "metric-card-warning")
    else:
        render_metric("Avg Score", "0.0", "No data", "metric-card-warning")
with col5:
    filtered_cve_ids = fdf['cve_id'].unique()
    cnt = df_products[df_products['cve_id'].isin(filtered_cve_ids)]['product'].nunique()
    render_metric("Products", cnt, "Affected", "metric-card-success")


# CHARTS
st.write("")
st.subheader("Analysis")

if fdf.empty:
    st.warning("No data matches your filters.")
    st.stop()

# Row 1: Trends & Severity
c1, c2 = st.columns([2, 1])
with c1:
    with st.container(border=True):
        st.caption("VULNERABILITY TRENDS")
        ts = fdf.set_index('published_date').resample('ME').size().reset_index(name='count')
        if not ts.empty:
            fig = px.bar(ts, x='published_date', y='count', color_discrete_sequence=['#2563EB'])
            fig.update_layout(height=280, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="")
            st.plotly_chart(fig, use_container_width=True)

with c2:
    with st.container(border=True):
        st.caption("SEVERITY DISTRIBUTION")
        sev = fdf['cvss_v31_severity'].value_counts()
        colors = {'CRITICAL':'#DC2626', 'HIGH':'#EA580C', 'MEDIUM':'#D97706', 'LOW':'#059669', 'UNKNOWN':'#9CA3AF'}
        if not sev.empty:
            fig = px.pie(values=sev.values, names=sev.index, color=sev.index, color_discrete_map=colors, hole=0.7)
            fig.update_layout(height=280, margin=dict(l=0,r=0,t=10,b=0), showlegend=False)
            fig.update_traces(textinfo='percent+label')
            evt_sev = st.plotly_chart(fig, use_container_width=True, on_select="rerun", selection_mode="points", key="chart_sev")
            if evt_sev.selection and evt_sev.selection.points:
                point = evt_sev.selection.points[0]
                sel_val = sev.index[point.point_index]
                if sel_val not in st.session_state.filter_severity:
                    st.session_state.filter_severity.append(sel_val)
                    st.rerun()

# Row 2: CWE & Category
c3, c4 = st.columns(2)
with c3:
    with st.container(border=True):
        st.caption("TOP WEAKNESS TYPES (CWE)")
        if not df_cwes.empty:
            filtered_cwes = df_cwes[df_cwes['cve_id'].isin(fdf['cve_id'])]
            if not filtered_cwes.empty:
                cwes = filtered_cwes['cwe_id'].value_counts().head(8)
                cwe_df = pd.DataFrame({'id': cwes.index, 'count': cwes.values})
                cwe_df['name'] = cwe_df['id'].apply(get_cwe_name)
                # Create clickable labels pointing to internal CWE page
                cwe_df['label_link'] = cwe_df['id'].apply(lambda c: f'<a href="?page=cwe&id={c}" target="_self" style="text-decoration:none; color:inherit;">{c}</a>')
                
                fig = px.bar(cwe_df, x='count', y='label_link', orientation='h', color='count', color_continuous_scale='Reds', hover_data=['name', 'id'])
                fig.update_layout(height=250, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="", coloraxis_showscale=False)
                fig.update_yaxes(tickmode='array', tickvals=list(range(len(cwes))), ticktext=cwe_df['label_link'].tolist())
                evt_cwe = st.plotly_chart(fig, use_container_width=True, on_select="rerun", selection_mode="points", key="chart_cwe")
                if evt_cwe.selection and evt_cwe.selection.points:
                    point = evt_cwe.selection.points[0]
                    # Get raw CWE ID from dataframe
                    sel_val = cwe_df.iloc[point.point_index]['id']
                    if sel_val not in st.session_state.filter_cwe:
                        st.session_state.filter_cwe.append(sel_val)
                        st.rerun()

with c4:
    with st.container(border=True):
        st.caption("VULNERABILITY CATEGORIES")
        vtypes = fdf['vuln_type'].value_counts()
        if not vtypes.empty:
            fig = px.bar(x=vtypes.values, y=vtypes.index, orientation='h', color=vtypes.values, color_continuous_scale='Blues')
            fig.update_layout(height=250, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="", coloraxis_showscale=False)
            evt_cat = st.plotly_chart(fig, use_container_width=True, on_select="rerun", selection_mode="points", key="chart_cat")
            if evt_cat.selection and evt_cat.selection.points:
                point = evt_cat.selection.points[0]
                sel_val = vtypes.index[point.point_index]
                if sel_val not in st.session_state.filter_type:
                    st.session_state.filter_type.append(sel_val)
                    st.rerun()

# Row 3: OWASP & Heatmap
c5, c6 = st.columns(2)
with c5:
    with st.container(border=True):
        st.caption("OWASP TOP 10 (2021) MAPPING")
        owasp = fdf['owasp'].value_counts()
        if not owasp.empty:
            fig = px.bar(x=owasp.values, y=owasp.index, orientation='h', color=owasp.values, color_continuous_scale='Purples')
            fig.update_layout(height=250, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="", coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)

with c6:
    with st.container(border=True):
        st.caption("VULN TYPE HEATMAP (YEARLY)")
        # Prepare Heapmap Data
        df_hm = fdf.copy()
        df_hm['year'] = df_hm['published_date'].dt.year
        hm_data = df_hm.groupby(['vuln_type', 'year']).size().reset_index(name='count')
        if not hm_data.empty:
            fig = px.density_heatmap(hm_data, x='year', y='vuln_type', z='count', color_continuous_scale='Viridis')
            fig.update_layout(height=250, margin=dict(l=0,r=0,t=10,b=0), xaxis_title="", yaxis_title="")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Not enough data for heatmap")

# LIST
st.write("")
st.subheader("Vulnerabilities")
csv = fdf.to_csv(index=False).encode('utf-8')
st.download_button("Download CSV", csv, "cve_data.csv", "text/csv")

# Custom Table
cols = ['cve_id', 'published_date', 'cvss_v31_severity', 'cvss_v31_base_score', 'is_kev', 'description_en', 'vuln_type', 'CWE_LINK', 'owasp']
# Prepare view dataframe
view_fdf = fdf.copy()
view_fdf['LINK'] = view_fdf['cve_id'].apply(lambda x: f"?cve={x}")
view_fdf['cve_id'] = view_fdf['cve_id'].apply(lambda x: f"?cve={x}")
view_fdf['CWE_LINK'] = view_fdf['cwe_ids'].apply(lambda x: f"?page=cwe&id={x.split(',')[0].strip()}" if x else None)
# Add KEV emoji indicator
if 'is_kev' in view_fdf.columns:
    view_fdf['is_kev'] = view_fdf['is_kev'].apply(lambda x: "🚨" if x else "")
else:
    view_fdf['is_kev'] = ""

st.dataframe(
    view_fdf[['LINK'] + cols].sort_values('published_date', ascending=False),
    use_container_width=True,
    column_config={
        "LINK": st.column_config.LinkColumn("", display_text="Open", width=60),
        "cve_id": st.column_config.LinkColumn("ID", display_text=r"\?cve=(.*)", width=120),
        "published_date": st.column_config.DateColumn("Date", format="YYYY-MM-DD"),
        "cvss_v31_severity": "Severity",
        "cvss_v31_base_score": st.column_config.NumberColumn("Score", format="%.1f"),
        "is_kev": st.column_config.TextColumn("KEV", width=50, help="Known Exploited Vulnerability"),
        "description_en": st.column_config.TextColumn("Description", width="large"),
        "vuln_type": "Type",
        "CWE_LINK": st.column_config.LinkColumn("CWE", display_text=r"id=([^&]*)"),
        "owasp": "OWASP Category"
    },
    height=800,
    hide_index=True
)



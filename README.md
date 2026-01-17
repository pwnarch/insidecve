# CVE  Dashboard

Open-source vulnerability intelligence platform. Select any vendor from CVEDetails.com, build their CVE database, and analyze security trends with interactive dashboards.

## Features

- **Multi-Vendor Support**: Browse and select from thousands of vendors (A-Z)
- **On-Demand Data**: Only fetch data when you click "Build" - no automatic scraping
- **Update Button**: Refresh existing vendors to get only new CVEs
- **Interactive Dashboard**: Filter by date, severity, products
- **Visualizations**: Timeline, severity distribution, top products
- **Export**: Download filtered data as CSV

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium

# Run the dashboard
streamlit run app.py
```

## Usage

1. **First Run**: Click "Fetch Vendor List" to load all vendors from CVEDetails.com
2. **Add a Company**: Select a vendor from the dropdown, click "Build"
3. **View Dashboard**: Select a company from "Your Companies" to see analytics
4. **Update Data**: Click the refresh button (↻) next to any company to fetch new CVEs

## Architecture

```
┌─────────────────────────────────────────┐
│          Streamlit Dashboard            │
├─────────────────────────────────────────┤
│  [Select Vendor ▼] [Build] [Update ↻]   │
├─────────────────────────────────────────┤
│  KPIs | Charts | Data Table | Export    │
└─────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│           DuckDB Storage                │
│  - cves (with vendor_id)                │
│  - products                             │
│  - weaknesses                           │
│  - vendor_metadata                      │
└─────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│         CVEDetails.com Scraper          │
│  - Vendor A-Z discovery                 │
│  - Product list per vendor              │
│  - CVE details per product              │
└─────────────────────────────────────────┘
```

## Project Structure

```
├── app.py                    # Streamlit dashboard
├── src/
│   ├── vendor_scraper.py     # A-Z vendor discovery & CVE scraping
│   ├── cvedetails_fetcher.py # CVE detail extraction
│   ├── storage.py            # DuckDB database layer
│   ├── data_fetcher.py       # NVD/V5 API fetchers (optional)
│   └── normalizer.py         # Data normalization
├── cache/
│   └── vendors.json          # Cached vendor list
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- Playwright (for web scraping)
- Streamlit (for dashboard)
- DuckDB (for storage)
- Plotly (for charts)

## Data Sources

- **CVEDetails.com**: Vendor/product/CVE mapping, CVSS scores, CWE IDs
- **NVD API** (optional): Official vulnerability data

## License

MIT

# SolarWinds CVE Pipeline and Dashboard

This project provides a robust pipeline to fetch, analyze, and visualize SolarWinds-related CVEs.

## Features
- **Data Collection**: Fetches from Official CVE List V5 and NVD API 2.0.
- **Enrichment**: Normalizes CVSS scores, weaknesses (CWE), and product information.
- **Storage**: Uses DuckDB for high-performance analytics and supports Parquet/CSV exports.
- **Visualization**: Interactive Streamlit dashboard for trends and insights.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

### 1. Update Data
Run the pipeline to fetch and update CVE data.
```bash
python pipeline.py
```
Options:
- `--input [file]`: Path to CVE ID list (default: `solarwinds_cve_ids.txt`)
- `--scrape`: Enable "best effort" scraping of CVEDetails to find product mappings.
- `--nvd-key [key]`: NVD API Key (increases rate limit).
- `--db [path]`: Database path (default: `solarwinds_cves.duckdb`).

### 2. View Dashboard
Launch the dashboard to explore the data.
```bash
streamlit run app.py
```

## Project Structure
- `pipeline.py`: Main data ingestion script.
- `app.py`: Analytics dashboard.
- `src/`: Source modules.
    - `data_fetcher.py`: API interactions (NVD/V5).
    - `normalizer.py`: Data cleaning.
    - `storage.py`: DuckDB and file operations.
    - `scraper.py`: Playwright scraper.
- `cache/`: Local cache for API responses.

## Troubleshooting
- **Rate Limits**: If NVD fetches are slow/failing 403, obtain an API key and pass it via `--nvd-key`.
- **Scraping Errors**: Scraping depends on `cvedetails.com` structure. If it fails, the pipeline will continue with NVD data only.
- **Dependencies**: Ensure you are in the virtual environment.

from datetime import datetime

class Normalizer:
    def normalize(self, cve_id, nvd_data, v5_data):
        record = {
            "cve_id": cve_id,
            "published_date": None,
            "last_modified_date": None,
            "description_en": "",
            "source_flags": [],
            "cvss_v31_base_score": None,
            "cvss_v31_severity": None,
            "cvss_v31_vector": None,
            "cvss_v4_base_score": None,
            "cvss_v4_severity": None,
            "cvss_v4_vector": None,
            "cwe_ids": [],
            "reference_urls": [],
            "products": []  # Will store CPE strings or simplified product names
        }

        # --- Process NVD Data ---
        if nvd_data and "vulnerabilities" in nvd_data:
            vuln_item = nvd_data["vulnerabilities"][0].get("cve", {})
            record["source_flags"].append("nvd")
            
            # Dates
            record["published_date"] = vuln_item.get("published")
            record["last_modified_date"] = vuln_item.get("lastModified")

            # Description
            for desc in vuln_item.get("descriptions", []):
                if desc.get("lang") == "en":
                    record["description_en"] = desc.get("value")
                    break

            # Metrics (CVSS)
            metrics = vuln_item.get("metrics", {})
            
            # V3.1
            if "cvssMetricV31" in metrics:
                v31 = metrics["cvssMetricV31"][0].get("cvssData", {})
                record["cvss_v31_base_score"] = v31.get("baseScore")
                record["cvss_v31_severity"] = v31.get("baseSeverity")
                record["cvss_v31_vector"] = v31.get("vectorString")
            
            # V4.0
            if "cvssMetricV40" in metrics:
                v4 = metrics["cvssMetricV40"][0].get("cvssData", {})
                record["cvss_v4_base_score"] = v4.get("baseScore")
                record["cvss_v4_severity"] = v4.get("baseSeverity")
                record["cvss_v4_vector"] = v4.get("vectorString")

            # Weaknesses (CWE)
            for weak in vuln_item.get("weaknesses", []):
                for desc in weak.get("description", []):
                     if desc.get("lang") == "en":
                         cwe = desc.get("value")
                         if cwe and cwe not in record["cwe_ids"]:
                             record["cwe_ids"].append(cwe)

            # References
            for ref in vuln_item.get("references", []):
                url = ref.get("url")
                if url and url not in record["reference_urls"]:
                    record["reference_urls"].append(url)

            # Configurations (CPE)
            # This is complex, but we want leaf nodes
            if "configurations" in vuln_item:
                for config in vuln_item["configurations"]:
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            cpe = cpe_match.get("criteria")
                            if cpe and cpe not in record["products"]:
                                record["products"].append(cpe)

        # --- Process V5 Data (Fallback/Enrichment) ---
        if v5_data:
            record["source_flags"].append("v5")
            cve_meta = v5_data.get("cveMetadata", {})
            containers = v5_data.get("containers", {}).get("cna", {})

            # Fallback for dates if NVD missing
            if not record["published_date"]:
                record["published_date"] = cve_meta.get("datePublished")
            if not record["last_modified_date"]:
                record["last_modified_date"] = cve_meta.get("dateUpdated")

            # Fallback for Description
            if not record["description_en"]:
                for desc in containers.get("descriptions", []):
                    if desc.get("lang") == "en":
                        record["description_en"] = desc.get("value")
                        break

            # Fallback for References
            for ref in containers.get("references", []):
                url = ref.get("url")
                if url and url not in record["reference_urls"]:
                     record["reference_urls"].append(url)
            
            # Additional Weaknesses?
            for prob in containers.get("problemTypes", []):
                 for desc in prob.get("descriptions", []):
                     if desc.get("lang") == "en":
                         # Sometimes it's text, sometimes CWE-ID
                         val = desc.get("cweId") or desc.get("description")
                         if val and val.startswith("CWE") and val not in record["cwe_ids"]:
                             record["cwe_ids"].append(val)

        # Final cleanup
        record["source_flags"] = ",".join(record["source_flags"])
        record["cwe_ids"] = ",".join(record["cwe_ids"])
        record["reference_urls"] = ",".join(record["reference_urls"])
        # Products are kept as list for now, or join them? 
        # For DuckDB CSV export, JSON or string is better.
        # Let's stringify for simple storage, but logic might need structured output.
        # We will separate product table logic in Storage if needed.
        # For now, let's keep it simple: stringify with a delimiter
        record["products"] = ";".join(record["products"])

        return record

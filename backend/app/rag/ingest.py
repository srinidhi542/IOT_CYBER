import os
import sys
import json
import time
import argparse
import logging
from typing import List, Dict, Any, Optional
import httpx

from app.rag.vector_store import get_vector_store, Document
from app.rag.embeddings import get_embedding_model

logger = logging.getLogger(__name__)

# Cache directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE_DIR = os.path.join(BASE_DIR, "data", "rag_cache")
SEED_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents", "knowledge_base")


class ThreatIntelIngester:
    """
    Ingests authoritative threat intelligence from real feeds:
    1. MITRE ATT&CK (Enterprise & ICS STIX 2.1 bundles)
    2. NVD CVE API 2.0 (IoT-filtered vulnerabilities)
    3. CISA Known Exploited Vulnerabilities (KEV) feed + CISA Advisories
    4. NIST SP 800-213 & OWASP IoT Top 10 guidance documents
    Includes local raw-data caching and offline seed fallback.
    """

    def __init__(self, cache_dir: str = CACHE_DIR, offline_seed_dir: str = SEED_DIR):
        self.cache_dir = cache_dir
        self.offline_seed_dir = offline_seed_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.vector_store = get_vector_store()
        self.embedding_model = get_embedding_model()

    # -------------------------------------------------------------
    # 1. MITRE ATT&CK (STIX 2.x Ingestion)
    # -------------------------------------------------------------
    def ingest_mitre(self, refresh: bool = False) -> List[Document]:
        cache_file = os.path.join(self.cache_dir, "mitre_enterprise_ics.json")
        data = None

        if not refresh and os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"Loaded {len(data)} cached MITRE ATT&CK records.")
            except Exception as e:
                logger.warning(f"Failed to read cached MITRE data: {e}")

        if not data:
            logger.info("Downloading official MITRE ATT&CK STIX bundles...")
            urls = [
                ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json", "Enterprise"),
                ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json", "ICS")
            ]
            raw_objects = []
            for url, domain in urls:
                try:
                    with httpx.Client(timeout=15.0) as client:
                        resp = client.get(url)
                        if resp.status_code == 200:
                            bundle = resp.json()
                            for obj in bundle.get("objects", []):
                                if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                                    obj["_domain"] = domain
                                    raw_objects.append(obj)
                            logger.info(f"Successfully fetched MITRE {domain} bundle ({len(raw_objects)} techniques so far).")
                except Exception as e:
                    logger.warning(f"Could not download live MITRE {domain} bundle: {e}")

            if raw_objects:
                data = raw_objects
                try:
                    with open(cache_file, "w", encoding="utf-8") as f:
                        json.dump(data, f)
                except Exception as e:
                    logger.warning(f"Failed to cache MITRE bundle: {e}")
            else:
                logger.info("Using offline seed dataset for MITRE ATT&CK techniques.")
                seed_file = os.path.join(self.offline_seed_dir, "mitre_attack.json")
                if os.path.exists(seed_file):
                    with open(seed_file, "r", encoding="utf-8") as f:
                        data = json.load(f)

        documents = []
        if data:
            for item in data:
                # Format depends on whether it's STIX object or seed JSON
                if "external_references" in item:
                    # STIX format
                    ext_refs = item.get("external_references", [])
                    mitre_id = next((r["external_id"] for r in ext_refs if r.get("source_name") in ["mitre-attack", "mitre-ics-attack"]), "")
                    url = next((r["url"] for r in ext_refs if "url" in r), f"https://attack.mitre.org/techniques/{mitre_id}/")
                    name = item.get("name", "")
                    desc = item.get("description", "")
                    tactics = [p.get("phase_name", "") for p in item.get("kill_chain_phases", [])]
                    tactic_str = ", ".join(tactics) or "Impact"
                else:
                    # Seed JSON format
                    mitre_id = item.get("id", "")
                    name = item.get("name", "")
                    tactic_str = item.get("tactic", "Impact")
                    desc = item.get("description", "")
                    url = item.get("url", f"https://attack.mitre.org/techniques/{mitre_id}/")

                if not mitre_id:
                    continue

                content = (
                    f"MITRE ATT&CK Technique {mitre_id}: {name}\n"
                    f"Tactic: {tactic_str}\n"
                    f"Description: {desc}\n"
                    f"URL: {url}"
                )

                documents.append(Document(
                    id=mitre_id,
                    content=content,
                    metadata={
                        "doc_type": "mitre_attack",
                        "id": mitre_id,
                        "name": name,
                        "tactic": tactic_str,
                        "url": url,
                        "source": "MITRE ATT&CK"
                    }
                ))

        logger.info(f"Processed {len(documents)} MITRE ATT&CK documents.")
        return documents

    # -------------------------------------------------------------
    # 2. NVD CVE Ingestion (IoT Filtered)
    # -------------------------------------------------------------
    def ingest_nvd_cves(self, refresh: bool = False) -> List[Document]:
        cache_file = os.path.join(self.cache_dir, "nvd_cves.json")
        data = None

        if not refresh and os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"Loaded {len(data)} cached NVD CVE records.")
            except Exception as e:
                logger.warning(f"Failed to read cached CVE data: {e}")

        if not data:
            logger.info("Fetching IoT-relevant CVEs from NVD API 2.0...")
            api_key = os.environ.get("NVD_API_KEY", "").strip()
            headers = {"apiKey": api_key} if api_key else {}
            keywords = ["Mirai", "telnet router", "camera injection", "MQTT", "CoAP"]
            fetched_cves = []

            for kw in keywords:
                try:
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage=10"
                    with httpx.Client(timeout=10.0) as client:
                        resp = client.get(url, headers=headers)
                        if resp.status_code == 200:
                            nvd_res = resp.json()
                            for vuln in nvd_res.get("vulnerabilities", []):
                                cve = vuln.get("cve", {})
                                fetched_cves.append(cve)
                        # Rate limit throttle: 0.6s with API key, 2.5s without
                        time.sleep(0.6 if api_key else 2.0)
                except Exception as e:
                    logger.warning(f"NVD query for keyword '{kw}' skipped: {e}")

            if fetched_cves:
                data = fetched_cves
                try:
                    with open(cache_file, "w", encoding="utf-8") as f:
                        json.dump(data, f)
                except Exception as e:
                    logger.warning(f"Failed to cache NVD records: {e}")
            else:
                logger.info("Using offline seed dataset for NVD CVEs.")
                seed_file = os.path.join(self.offline_seed_dir, "cve_database.json")
                if os.path.exists(seed_file):
                    with open(seed_file, "r", encoding="utf-8") as f:
                        data = json.load(f)

        documents = []
        if data:
            for item in data:
                if "descriptions" in item:
                    # NVD API 2.0 schema
                    cve_id = item.get("id", "")
                    descriptions = item.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                    metrics = item.get("metrics", {})
                    cvss_score = 7.5
                    severity = "HIGH"
                    # Try CVSS v3.1
                    cvss31 = metrics.get("cvssMetricV31", [])
                    if cvss31:
                        cvss_data = cvss31[0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 7.5))
                        severity = cvss_data.get("baseSeverity", "HIGH")
                    affected = "Embedded Linux / IoT Network Devices"
                    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                else:
                    # Seed JSON schema
                    cve_id = item.get("cve_id", "")
                    desc = item.get("description", "")
                    cvss_score = float(item.get("cvss_score", 7.5))
                    severity = item.get("severity", "HIGH")
                    affected = item.get("affected_systems", "IoT Devices")
                    url = item.get("url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")

                if not cve_id:
                    continue

                content = (
                    f"Vulnerability Record {cve_id} (CVSS: {cvss_score}, Severity: {severity})\n"
                    f"Affected Systems: {affected}\n"
                    f"Details: {desc}\n"
                    f"URL: {url}"
                )

                documents.append(Document(
                    id=cve_id,
                    content=content,
                    metadata={
                        "doc_type": "cve",
                        "id": cve_id,
                        "cvss": cvss_score,
                        "severity": severity,
                        "affected": affected,
                        "url": url,
                        "source": "NVD CVE"
                    }
                ))

        logger.info(f"Processed {len(documents)} NVD CVE documents.")
        return documents

    # -------------------------------------------------------------
    # 3. CISA KEV & Advisories Ingestion
    # -------------------------------------------------------------
    def ingest_cisa_advisories(self, refresh: bool = False) -> List[Document]:
        cache_file = os.path.join(self.cache_dir, "cisa_feed.json")
        data = None

        if not refresh and os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"Loaded {len(data)} cached CISA advisory records.")
            except Exception as e:
                logger.warning(f"Failed to read cached CISA data: {e}")

        if not data:
            logger.info("Fetching CISA Known Exploited Vulnerabilities feed...")
            try:
                url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                with httpx.Client(timeout=10.0) as client:
                    resp = client.get(url)
                    if resp.status_code == 200:
                        feed = resp.json()
                        vulns = feed.get("vulnerabilities", [])
                        # Filter to IoT/Network router/camera/gateway related
                        iot_terms = ["router", "camera", "dvr", "gateway", "mirai", "iot", "telnet", "firmware", "zyxel", "hikvision"]
                        filtered = [
                            v for v in vulns
                            if any(term in (v.get("shortDescription", "") + " " + v.get("product", "")).lower() for term in iot_terms)
                        ]
                        data = filtered[:50]
                        with open(cache_file, "w", encoding="utf-8") as f:
                            json.dump(data, f)
            except Exception as e:
                logger.warning(f"Could not download live CISA KEV feed: {e}")

        if not data:
            logger.info("Using offline seed dataset for CISA advisories.")
            seed_file = os.path.join(self.offline_seed_dir, "cisa_advisories.json")
            if os.path.exists(seed_file):
                with open(seed_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

        documents = []
        if data:
            for item in data:
                if "cveID" in item:
                    # KEV feed schema
                    adv_id = f"CISA-KEV-{item.get('cveID')}"
                    title = f"CISA KEV: {item.get('vendorProject')} {item.get('product')}"
                    desc = item.get("shortDescription", "")
                    date = item.get("dateAdded", "")
                    url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={item.get('cveID')}"
                else:
                    # Seed advisory schema
                    adv_id = item.get("id", "")
                    title = item.get("title", "")
                    desc = item.get("summary", "")
                    date = item.get("release_date", "")
                    url = item.get("url", f"https://www.cisa.gov/news-events/cybersecurity-advisories/{adv_id.lower()}")

                if not adv_id:
                    continue

                content = (
                    f"CISA Security Advisory {adv_id}: {title} (Released: {date})\n"
                    f"Summary: {desc}\n"
                    f"URL: {url}"
                )

                documents.append(Document(
                    id=adv_id,
                    content=content,
                    metadata={
                        "doc_type": "cisa_advisory",
                        "id": adv_id,
                        "title": title,
                        "date": date,
                        "url": url,
                        "source": "CISA"
                    }
                ))

        logger.info(f"Processed {len(documents)} CISA documents.")
        return documents

    # -------------------------------------------------------------
    # 4. NIST IoT & OWASP Guidelines Ingestion
    # -------------------------------------------------------------
    def ingest_guidelines(self) -> List[Document]:
        seed_file = os.path.join(self.offline_seed_dir, "iot_guidelines.json")
        documents = []
        if os.path.exists(seed_file):
            try:
                with open(seed_file, "r", encoding="utf-8") as f:
                    guidelines = json.load(f)
                for item in guidelines:
                    std = item.get("standard", "NIST Guidance")
                    title = item.get("title", "")
                    guidance = item.get("guidance", "")
                    url = item.get("url", "https://csrc.nist.gov")
                    doc_id = std.replace(" ", "-").replace("/", "-")

                    content = (
                        f"Standard: {std} - {title}\n"
                        f"Guidance: {guidance}\n"
                        f"URL: {url}"
                    )
                    documents.append(Document(
                        id=doc_id,
                        content=content,
                        metadata={
                            "doc_type": "guideline",
                            "id": doc_id,
                            "title": title,
                            "url": url,
                            "source": "NIST/OWASP"
                        }
                    ))
            except Exception as e:
                logger.warning(f"Could not load guidelines: {e}")

        logger.info(f"Processed {len(documents)} cybersecurity guideline documents.")
        return documents

    # -------------------------------------------------------------
    # Full Ingestion Pipeline
    # -------------------------------------------------------------
    def run_ingestion(self, refresh: bool = False) -> Dict[str, Any]:
        logger.info(f"Beginning threat intelligence ingestion (refresh={refresh})...")
        t0 = time.time()

        all_docs: List[Document] = []
        all_docs.extend(self.ingest_mitre(refresh=refresh))
        all_docs.extend(self.ingest_nvd_cves(refresh=refresh))
        all_docs.extend(self.ingest_cisa_advisories(refresh=refresh))
        all_docs.extend(self.ingest_guidelines())

        if not all_docs:
            logger.warning("No threat intelligence documents found to ingest.")
            return {"status": "empty", "total_indexed": 0}

        # Compute embeddings in batches
        logger.info(f"Computing embeddings for {len(all_docs)} documents...")
        batch_size = 64
        for i in range(0, len(all_docs), batch_size):
            batch = all_docs[i:i + batch_size]
            texts = [doc.content for doc in batch]
            embs = self.embedding_model.encode(texts)
            for doc, emb in zip(batch, embs):
                doc.embedding = emb

        # Upsert into vector store
        added_count = self.vector_store.add_documents(all_docs)
        duration_s = round(time.time() - t0, 2)

        stats = self.vector_store.get_stats()
        stats["last_refresh"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        stats["ingest_duration_seconds"] = duration_s

        # Write metadata status file in cache
        status_file = os.path.join(self.cache_dir, "ingest_status.json")
        try:
            with open(status_file, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to write ingest status file: {e}")

        logger.info(f"Ingestion complete: {added_count} documents indexed in {duration_s}s.")
        return stats


if __name__ == "__main__":
    from datetime import datetime
    parser = argparse.ArgumentParser(description="IoT Sentinel Threat Intelligence RAG Ingester")
    parser.add_argument("--refresh", action="store_true", help="Force refresh from authoritative online sources")
    args = parser.parse_args()

    ingester = ThreatIntelIngester()
    results = ingester.run_ingestion(refresh=args.refresh)
    print(json.dumps(results, indent=2))

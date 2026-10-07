#!/usr/bin/env python3
"""
CWE Enrichment from CNA — native pycti connector

Strategy (bulk, fast):
  1. Download full NVD CVE dataset in bulk (2000/page) → build cve_id → [CWE-XX] map
  2. Paginate all OpenCTI vulnerabilities
  3. For each CVE without x_opencti_cwe, build a STIX Vulnerability object
     with x_opencti_cwe set and send as a bundle → OpenCTI merges by name

Labels dropped in favour of the structured x_opencti_cwe field.
"""

import json
import time
import urllib.request
from datetime import datetime, timezone

import stix2
from pycti import OpenCTIConnectorHelper, get_config_variable

NVD_BASE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SKIP_VALUES = {"NVD-CWE-OTHER", "NVD-CWE-NOINFO"}
NVD_PAGE_SIZE  = 2000
NVD_DELAY      = 0.7   # ~50 req/30s with API key
BUNDLE_SIZE    = 200   # objects per send_stix2_bundle call


class CweEnrichConnector:
    def __init__(self, config: dict):
        self.helper = OpenCTIConnectorHelper(config)
        self.nvd_api_key = get_config_variable(
            "NVD_API_KEY", ["cwe_enrich", "nvd_api_key"], config
        )
        self.batch_size = int(
            get_config_variable(
                "CWE_BATCH_SIZE", ["cwe_enrich", "batch_size"], config, default=500
            )
        )

    # ── NVD bulk download ────────────────────────────────────────────────────

    def _fetch_nvd_bulk(self) -> dict[str, list[str]]:
        """Download entire NVD dataset, return {cve_id: [CWE-XX, ...]}."""
        cve_cwe_map: dict[str, list[str]] = {}
        start = 0

        self.helper.log_info("Downloading NVD bulk dataset …")
        while True:
            url = f"{NVD_BASE_URL}?resultsPerPage={NVD_PAGE_SIZE}&startIndex={start}"
            req = urllib.request.Request(
                url,
                headers={
                    "apiKey": self.nvd_api_key,
                    "User-Agent": "cwe-enrich-connector/4.0",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.load(resp)
            except Exception as exc:
                self.helper.log_error(f"NVD bulk fetch error at startIndex={start}: {exc}")
                time.sleep(NVD_DELAY * 4)
                continue  # retry same page
            finally:
                time.sleep(NVD_DELAY)

            total = data.get("totalResults", 0)
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                cve_id = cve["id"]
                cwes = []
                seen: set[str] = set()
                for weakness in cve.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        val = desc.get("value", "").strip().upper()
                        if (
                            val.startswith("CWE-")
                            and val not in NVD_SKIP_VALUES
                            and val not in seen
                        ):
                            seen.add(val)
                            cwes.append(val)
                if cwes:
                    cve_cwe_map[cve_id] = cwes

            start += NVD_PAGE_SIZE
            self.helper.log_info(
                f"  NVD progress: {min(start, total)}/{total} "
                f"({len(cve_cwe_map)} CVEs with CWE so far)"
            )
            if start >= total:
                break

        self.helper.log_info(
            f"NVD download complete — {len(cve_cwe_map)} CVEs have CWE data"
        )
        return cve_cwe_map

    # ── Main processing ──────────────────────────────────────────────────────

    def _process(self, work_id: str) -> None:
        self.helper.log_info("CWE enrichment run starting …")

        # Step 1: build local NVD map (bulk)
        cve_cwe_map = self._fetch_nvd_bulk()

        # Step 2: paginate OpenCTI vulnerabilities, build STIX bundles
        stats = {"scanned": 0, "enriched": 0, "bundles_sent": 0}
        after = None
        bundle_objects: list = []

        def _flush(force: bool = False):
            if bundle_objects and (force or len(bundle_objects) >= BUNDLE_SIZE):
                bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
                self.helper.send_stix2_bundle(
                    bundle.serialize(),
                    update=True,
                    work_id=work_id,
                )
                stats["bundles_sent"] += 1
                bundle_objects.clear()

        while True:
            result = self.helper.api.vulnerability.list(
                first=self.batch_size,
                after=after,
                orderBy="created_at",
                orderMode="asc",
                withPagination=True,
                customAttributes="id name x_opencti_cwe standard_id",
            )
            entities  = result.get("entities", result.get("edges", []))
            page_info = result.get("pagination", result.get("pageInfo", {}))

            for node in entities:
                if "node" in node:
                    node = node["node"]
                name = node.get("name", "")
                if not name.upper().startswith("CVE-"):
                    continue

                # Skip if already enriched
                existing_cwe = node.get("x_opencti_cwe")
                if existing_cwe:
                    continue

                stats["scanned"] += 1
                cwes = cve_cwe_map.get(name.upper(), cve_cwe_map.get(name, []))
                if not cwes:
                    continue

                stats["enriched"] += 1

                # Build a STIX Vulnerability object with x_opencti_cwe set
                stix_vuln = stix2.Vulnerability(
                    id=node["standard_id"],
                    name=name,
                    allow_custom=True,
                    custom_properties={"x_opencti_cwe": cwes},
                )
                bundle_objects.append(stix_vuln)
                _flush()

                if stats["enriched"] % 1000 == 0:
                    self.helper.log_info(
                        f"  … {stats['scanned']} scanned | "
                        f"{stats['enriched']} enriched | "
                        f"{stats['bundles_sent']} bundles sent"
                    )

            if not page_info.get("hasNextPage"):
                break
            after = page_info["endCursor"]

        _flush(force=True)

        self.helper.log_info(
            f"CWE enrichment done — scanned={stats['scanned']} "
            f"enriched={stats['enriched']} bundles_sent={stats['bundles_sent']}"
        )

    def run(self) -> None:
        self.helper.log_info("CWE Enrichment from CNA connector starting …")
        duration_str = self.helper.connect_duration_period or "P1D"
        interval = self._parse_duration(duration_str)

        while True:
            try:
                current_time = int(time.time())
                state = self.helper.get_state() or {}
                last_run = state.get("last_run")
                if last_run is None or current_time - last_run >= interval:
                    now = datetime.fromtimestamp(current_time, tz=timezone.utc)
                    friendly_name = (
                        f"{self.helper.connect_name} run @ "
                        + now.strftime("%Y-%m-%d %H:%M:%S")
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        self._process(work_id)
                        self.helper.api.work.to_processed(work_id, "Completed")
                    except Exception as exc:
                        self.helper.log_error(f"Run failed: {exc}")
                        self.helper.api.work.to_processed(work_id, f"Run failed: {exc}")
                    self.helper.set_state({"last_run": int(time.time())})
                else:
                    remaining = interval - (current_time - last_run)
                    self.helper.log_info(f"Next run in {remaining}s")
            except Exception as exc:
                self.helper.log_error(f"Connector loop error: {exc}")
            time.sleep(60)

    @staticmethod
    def _parse_duration(iso: str) -> int:
        import re
        m = re.match(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", iso)
        if not m:
            return 86400
        days, hours, mins, secs = (int(x or 0) for x in m.groups())
        return days * 86400 + hours * 3600 + mins * 60 + secs

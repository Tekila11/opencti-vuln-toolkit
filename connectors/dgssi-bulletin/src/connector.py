#!/usr/bin/env python3
"""
DGSSI Bulletin Connector — external-import connector for OpenCTI

Scrapes dgssi.gov.ma/fr/bulletins/ and creates:

  Vulnerability bulletins:
    Report  ← bulletin metadata (title, ref, risk level, bilan, risks, solution)
      └─ Entities:   Vulnerability objects (CVEs already in OpenCTI via NVD)
                    System Identity objects (internal assets running affected software)
      └─ Observables: (linked automatically via existing CVE→CPE→System chain)
    ExternalReference  ← PDF + vendor advisory URLs

  Malware/threat bulletins:
    Report  ← same structure
      └─ Entities:   Malware object
      └─ Observables: File (SHA-256 hashes), IPv4-Addr (C2 IPs)

Reports are deduplicated by bulletin reference number stored in state.
Runs on the schedule defined by CONNECTOR_DURATION_PERIOD (default PT6H).
"""

import re
import time
from datetime import datetime, timedelta, timezone

import requests
import stix2
from pycti import (
    OpenCTIConnectorHelper,
    Report,
    get_config_variable,
)

from scraper import DgssiBulletin, fetch_bulletin, fetch_bulletin_urls

RISK_LABEL_MAP = {
    "critique": "Critique",
    "critical":  "Critique",
    "important": "Important",
    "modéré":    "Modéré",
    "moderate":  "Modéré",
    "faible":    "Faible",
    "low":       "Faible",
}

BUNDLE_SIZE = 50


class DgssiBulletinConnector:
    def __init__(self, config: dict):
        self.helper = OpenCTIConnectorHelper(config)
        self.confidence = int(
            get_config_variable(
                "DGSSI_CONFIDENCE",
                ["dgssi_bulletin", "confidence"],
                config,
                default=80,
            )
        )
        self.report_type = get_config_variable(
            "DGSSI_REPORT_TYPE",
            ["dgssi_bulletin", "report_type"],
            config,
            default="Bulletin DGSSI",
        )
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "dgssi-bulletin-connector/1.0"

        # in-memory caches per run
        self._cve_cache:     dict[str, dict | None] = {}
        self._malware_cache: dict[str, dict | None] = {}
        self._label_cache:   dict[str, str]         = {}  # value → id

    # ── OpenCTI lookup helpers ────────────────────────────────────────────────

    def _lookup_cve(self, cve_id: str) -> dict | None:
        if cve_id in self._cve_cache:
            return self._cve_cache[cve_id]
        result = self.helper.api.vulnerability.list(
            filters={
                "mode": "and",
                "filters": [{"key": ["name"], "values": [cve_id], "mode": "or"}],
                "filterGroups": [],
            },
            first=1,
            customAttributes="id standard_id name",
        )
        node = result[0] if result else None
        self._cve_cache[cve_id] = node
        return node

    def _lookup_or_create_malware(self, name: str) -> dict | None:
        if name in self._malware_cache:
            return self._malware_cache[name]
        result = self.helper.api.malware.list(
            filters={
                "mode": "and",
                "filters": [{"key": ["name"], "values": [name], "mode": "or"}],
                "filterGroups": [],
            },
            first=1,
            customAttributes="id standard_id name",
        )
        if result:
            node = result[0]
        else:
            node = self.helper.api.malware.create(
                name=name,
                is_family=False,
                confidence=self.confidence,
            )
        self._malware_cache[name] = node
        return node

    def _find_cpe_observables(self, cve_ids: list[str]) -> list[dict]:
        """
        For each CVE, return Software observables linked via Software → has → Vulnerability.
        """
        observables: dict[str, dict] = {}
        for cve_id in cve_ids:
            cve_node = self._lookup_cve(cve_id)
            if not cve_node:
                continue
            try:
                rels = self.helper.api.stix_core_relationship.list(
                    toId=cve_node["id"],
                    relationship_type="has",
                    first=100,
                )
            except Exception:
                continue
            for rel in (rels or []):
                from_obj = rel.get("from") or {}
                entity_type = from_obj.get("entity_type", "") or from_obj.get("type", "")
                if entity_type.lower() != "software":
                    continue
                sid = from_obj.get("id")
                standard_id = from_obj.get("standard_id")
                if sid and sid not in observables:
                    observables[sid] = {"id": sid, "standard_id": standard_id}
        return list(observables.values())

    def _find_affected_systems(self, cve_ids: list[str]) -> list[dict]:
        """
        For each CVE, query System → has → Vulnerability relationships directly.
        Returns unique System Identity objects.
        """
        systems: dict[str, dict] = {}
        for cve_id in cve_ids:
            cve_node = self._lookup_cve(cve_id)
            if not cve_node:
                continue
            try:
                rels = self.helper.api.stix_core_relationship.list(
                    toId=cve_node["id"],
                    relationship_type="has",
                    first=100,
                )
            except Exception:
                continue
            for rel in (rels or []):
                from_obj = rel.get("from") or {}
                entity_type = from_obj.get("entity_type", "") or from_obj.get("type", "")
                if entity_type.lower() != "system":
                    continue
                sid = from_obj.get("id")
                standard_id = from_obj.get("standard_id")
                if sid and sid not in systems:
                    systems[sid] = {"id": sid, "standard_id": standard_id}
        return list(systems.values())

    def _get_or_create_label(self, value: str) -> str | None:
        """Return label ID, creating it if it doesn't exist."""
        if value in self._label_cache:
            return self._label_cache[value]
        try:
            existing = self.helper.api.label.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": ["value"], "values": [value], "mode": "or"}],
                    "filterGroups": [],
                },
                first=1,
            )
            if existing:
                label_id = existing[0]["id"]
            else:
                color_map = {
                    "Critique": "#d32f2f",
                    "Important": "#f57c00",
                    "Modéré":    "#fbc02d",
                    "Faible":    "#388e3c",
                }
                created = self.helper.api.label.create(
                    value=value,
                    color=color_map.get(value, "#607d8b"),
                )
                label_id = created["id"] if created else None
            if label_id:
                self._label_cache[value] = label_id
            return label_id
        except Exception:
            return None

    def _get_dgssi_author_id(self) -> str | None:
        try:
            result = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": ["name"], "values": ["DGSSI"], "mode": "or"}],
                    "filterGroups": [],
                },
                first=1,
                customAttributes="id",
            )
            return result[0]["id"] if result else None
        except Exception:
            return None

    # ── Report building ───────────────────────────────────────────────────────

    def _build_content(self, b: DgssiBulletin) -> str:
        def row(label, value):
            return f"<tr><td><strong>{label}</strong></td><td>{value}</td></tr>"

        html = "<table>"
        html += row("Numéro de Référence", b.reference or "-")
        html += row("Date de publication", b.published or "-")
        html += row("Niveau de Risque", b.risk_level or "-")
        html += row("Niveau d'Impact", b.impact_level or "-")
        html += "</table>"

        if b.bilan:
            html += f"<h3>Bilan</h3><p>{b.bilan}</p>"

        if b.affected_systems:
            html += "<h3>Systèmes affectés</h3><ul>"
            for s in b.affected_systems:
                html += f"<li>{s}</li>"
            html += "</ul>"

        if b.cve_ids:
            html += "<h3>Identificateurs externes</h3><p>"
            html += ", ".join(b.cve_ids)
            html += "</p>"

        if b.risks:
            html += "<h3>Risques</h3><ul>"
            for r in b.risks:
                html += f"<li>{r}</li>"
            html += "</ul>"

        if b.solution:
            html += f"<h3>Solution</h3><p>{b.solution}</p>"

        if b.malware_names:
            html += "<h3>Malware</h3><p>"
            html += ", ".join(b.malware_names)
            html += "</p>"

        if b.ioc_hashes:
            html += f"<h3>Indicateurs — Hachages SHA-256</h3><ul>"
            for h in b.ioc_hashes:
                html += f"<li><code>{h}</code></li>"
            html += "</ul>"

        if b.ioc_ips:
            html += "<h3>Indicateurs — Adresses IP C2</h3><ul>"
            for ip in b.ioc_ips:
                html += f"<li><code>{ip}</code></li>"
            html += "</ul>"

        return html

    def _ingest_bulletin(self, b: DgssiBulletin, work_id: str, author_id: str | None) -> None:
        risk_normalized = RISK_LABEL_MAP.get(b.risk_level.lower(), b.risk_level)
        label_id        = self._get_or_create_label(risk_normalized) if risk_normalized else None

        # ── external references ───────────────────────────────────────────────
        ext_refs = []
        if b.pdf_url:
            ext_refs.append(stix2.ExternalReference(
                source_name="DGSSI PDF",
                url=b.pdf_url,
                description=f"Bulletin officiel DGSSI — {b.reference}",
            ))
        ext_refs.append(stix2.ExternalReference(
            source_name="DGSSI",
            url=b.url,
            external_id=b.reference,
        ))
        for url in b.reference_urls:
            ext_refs.append(stix2.ExternalReference(
                source_name="Référence vendeur",
                url=url,
            ))

        # ── published_by / created_by ─────────────────────────────────────────
        created_by_ref = None
        if author_id:
            try:
                obj = self.helper.api.identity.read(id=author_id)
                created_by_ref = obj.get("standard_id") if obj else None
            except Exception:
                pass

        # ── Report STIX object ────────────────────────────────────────────────
        published_dt = b.published or datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        try:
            pub_dt = datetime.strptime(published_dt, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pub_dt = datetime.now(tz=timezone.utc)

        object_refs: list = []

        # Resolve CVEs → Vulnerability standard_ids
        cve_nodes = []
        for cve_id in b.cve_ids:
            node = self._lookup_cve(cve_id)
            if node:
                cve_nodes.append(node)
                object_refs.append(node["standard_id"])

        # Resolve malware objects
        malware_nodes = []
        for name in b.malware_names:
            node = self._lookup_or_create_malware(name)
            if node:
                malware_nodes.append(node)
                object_refs.append(node["standard_id"])

        # Resolve CPE Software observables (Observables tab)
        cpe_nodes = []
        if b.cve_ids:
            cpe_nodes = self._find_cpe_observables(b.cve_ids)
            for cpe_node in cpe_nodes:
                sid = cpe_node.get("standard_id")
                if sid:
                    object_refs.append(sid)

        # Resolve affected internal systems (Entities tab)
        system_nodes = []
        if b.cve_ids:
            system_nodes = self._find_affected_systems(b.cve_ids)
            for sys_node in system_nodes:
                sid = sys_node.get("standard_id")
                if sid:
                    object_refs.append(sid)

        # Need at least one object_ref for a valid STIX Report
        if not object_refs:
            self.helper.log_info(f"  Skipping {b.reference} — no linked objects found in OpenCTI")
            return

        report_kwargs = dict(
            id=Report.generate_id(b.title, pub_dt),
            name=b.title,
            report_types=[self.report_type],
            published=pub_dt,
            description=b.bilan or b.title,
            object_refs=object_refs,
            external_references=ext_refs,
            confidence=self.confidence,
            allow_custom=True,
            x_opencti_content=self._build_content(b),
        )
        if created_by_ref:
            report_kwargs["created_by_ref"] = created_by_ref

        report_obj = stix2.Report(**report_kwargs)

        bundle_objects: list = [report_obj]

        # ── IOC observables (malware bulletins) ───────────────────────────────
        for sha256 in b.ioc_hashes:
            bundle_objects.append(stix2.File(
                hashes={"SHA-256": sha256},
                allow_custom=True,
                object_marking_refs=[stix2.TLP_WHITE],
            ))
        for ip in b.ioc_ips:
            if _is_public_ip(ip):
                bundle_objects.append(stix2.IPv4Address(
                    value=ip,
                    allow_custom=True,
                    object_marking_refs=[stix2.TLP_WHITE],
                ))

        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
        self.helper.send_stix2_bundle(
            bundle.serialize(),
            update=True,
            work_id=work_id,
        )

        # Apply risk label via API (STIX x_opencti_labels takes values not IDs)
        if label_id and risk_normalized:
            try:
                report_in_oc = self.helper.api.report.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": ["name"], "values": [b.title], "mode": "or"}],
                        "filterGroups": [],
                    }
                )
                if report_in_oc:
                    self.helper.api.stix_domain_object.add_label(
                        id=report_in_oc["id"],
                        label_id=label_id,
                    )
            except Exception as e:
                self.helper.log_warning(f"  Could not apply label to {b.reference}: {e}")

        self.helper.log_info(
            f"  Ingested: {b.reference} | CVEs={len(cve_nodes)} "
            f"CPEs={len(cpe_nodes)} systems={len(system_nodes)} "
            f"malware={len(malware_nodes)} hashes={len(b.ioc_hashes)} IPs={len(b.ioc_ips)}"
        )

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _process(self, work_id: str, last_run: int | None) -> None:
        self._cve_cache     = {}
        self._malware_cache = {}

        author_id = self._get_dgssi_author_id()
        if not author_id:
            self.helper.log_warning(
                "DGSSI Organization not found in OpenCTI — reports will have no author. "
                "Create an Organization named 'DGSSI' under Data > Entities."
            )

        # On first run: fetch all bulletins.
        # On subsequent runs: only fetch bulletins published on or after the
        # last-run date. The listing is newest-first so we stop early once we
        # hit a bulletin older than last_run, avoiding scraping all 500+ pages.
        since_date: str | None = None
        if last_run is not None:
            # Go back one extra day so runs within the same day don't miss
            # bulletins published after the previous run completed.
            last_run_dt = datetime.fromtimestamp(last_run, tz=timezone.utc)
            since_date = (last_run_dt - timedelta(days=1)).strftime("%Y-%m-%d")
            self.helper.log_info(f"Incremental run — fetching bulletins since {since_date}")
        else:
            self.helper.log_info("First run — fetching all bulletins")

        urls = fetch_bulletin_urls(self._session)
        self.helper.log_info(f"  {len(urls)} bulletin URLs found on listing page")

        ingested = updated = skipped = errors = 0

        total = len(urls)
        for i, url in enumerate(urls, 1):
            if i % 50 == 0 or i == 1:
                self.helper.log_info(f"  Progress: {i}/{total} | ingested={ingested} errors={errors}")

            try:
                bulletin = fetch_bulletin(url, self._session)
            except Exception as exc:
                self.helper.log_error(f"  Failed to fetch {url}: {exc}")
                errors += 1
                continue

            if not bulletin:
                errors += 1
                continue

            # Stop early on incremental runs: listing is newest-first, so once
            # we see a bulletin older than since_date we can stop.
            if since_date and bulletin.published and bulletin.published < since_date:
                self.helper.log_info(
                    f"  Reached bulletin dated {bulletin.published} < {since_date}, stopping."
                )
                break

            self._ingest_bulletin(bulletin, work_id, author_id)
            ingested += 1

        if urls:
            self.helper.set_state({"last_run": int(time.time())})
        self.helper.log_info(
            f"DGSSI run complete — ingested/updated={ingested} skipped={skipped} errors={errors}"
        )

    def run(self) -> None:
        self.helper.log_info("DGSSI Bulletin connector starting …")
        duration_str = self.helper.connect_duration_period or "PT6H"
        interval     = _parse_duration(duration_str)

        while True:
            try:
                current_time = int(time.time())
                state        = self.helper.get_state() or {}
                last_run     = state.get("last_run")

                if last_run is None or current_time - last_run >= interval:
                    now = datetime.fromtimestamp(current_time, tz=timezone.utc)
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id,
                        f"{self.helper.connect_name} run @ {now.strftime('%Y-%m-%d %H:%M:%S')}",
                    )
                    try:
                        self._process(work_id, last_run)
                        self.helper.api.work.to_processed(work_id, "Completed")
                    except Exception as exc:
                        self.helper.log_error(f"Run failed: {exc}")
                        self.helper.api.work.to_processed(work_id, f"Run failed: {exc}")
                else:
                    remaining = interval - (current_time - last_run)
                    self.helper.log_info(f"Next run in {remaining}s")
            except Exception as exc:
                self.helper.log_error(f"Connector loop error: {exc}")
            time.sleep(60)


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_public_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
        b = int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 127:
        return False
    return True


def _parse_duration(iso: str) -> int:
    m = re.match(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", iso)
    if not m:
        return 21600
    days, hours, mins, secs = (int(x or 0) for x in m.groups())
    return days * 86400 + hours * 3600 + mins * 60 + secs

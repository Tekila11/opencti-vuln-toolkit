#!/usr/bin/env python3
"""
Forescout Asset Connector — external-import connector for OpenCTI

Pulls the live device inventory from Forescout eyeSight via the Web API
and creates the following OpenCTI objects:

    System (Identity)      ← device record
    IPv4-Addr              ← IP address
    MAC-Addr               ← MAC address (when available)
    Hostname               ← hostname (when available)

    System → related-to → IPv4-Addr
    System → related-to → MAC-Addr
    System → related-to → Hostname
    System → related-to → Software (CPE)   ← linked to firmware/OS CPE already in OpenCTI

The System → Software(CPE) → has → CVE chain enables the "affected assets" view
in the OpenCTI dashboard once cve-cpe-mapper has run.

Runs on the schedule defined by CONNECTOR_DURATION_PERIOD (default P1D).
"""

import time
import urllib.parse
from datetime import datetime, timezone

import requests
import stix2
import urllib3
from pycti import (
    CustomObservableHostname,
    Identity as PyCTIIdentity,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)

# Suppress TLS warnings for self-signed Forescout appliance certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BUNDLE_SIZE = 200
PAGE_SIZE   = 500   # hosts per API page


class ForescoutSession:
    """Manages Forescout Web API session (token + automatic re-auth)."""

    def __init__(self, host: str, username: str, password: str, verify_tls: bool = False):
        self.base_url  = f"https://{host}"
        self.username  = username
        self.password  = password
        self.verify    = verify_tls
        self._token: str | None = None

    def _login(self) -> None:
        resp = requests.post(
            f"{self.base_url}/api/login",
            data={"username": self.username, "password": self.password},
            verify=self.verify,
            timeout=30,
        )
        resp.raise_for_status()
        self._token = resp.text.strip().strip('"')

    def get(self, path: str, params: dict | None = None, retry: bool = True) -> dict:
        if self._token is None:
            self._login()
        headers = {"Authorization": self._token}
        resp = requests.get(
            f"{self.base_url}{path}",
            headers=headers,
            params=params,
            verify=self.verify,
            timeout=60,
        )
        if resp.status_code == 401 and retry:
            self._login()
            return self.get(path, params=params, retry=False)
        resp.raise_for_status()
        return resp.json()


class ForescoutAssetConnector:
    def __init__(self, config: dict):
        self.helper = OpenCTIConnectorHelper(config)

        host     = get_config_variable("FORESCOUT_HOST",     ["forescout", "host"],     config)
        username = get_config_variable("FORESCOUT_USERNAME",  ["forescout", "username"],  config)
        password = get_config_variable("FORESCOUT_PASSWORD",  ["forescout", "password"],  config)
        verify   = get_config_variable("FORESCOUT_VERIFY_TLS", ["forescout", "verify_tls"], config, default=False)

        self.session = ForescoutSession(host, username, str(password), verify_tls=bool(verify))

        # Forescout property names to request for each host.
        # These must match actual eyeSight property names in your deployment.
        self.host_fields = get_config_variable(
            "FORESCOUT_HOST_FIELDS",
            ["forescout", "host_fields"],
            config,
            default="hostname,vendor,cl_vendor,cl_os,cl_patchlevel,cl_category,cl_model",
        )

        self.confidence = int(
            get_config_variable(
                "CONNECTOR_CONFIDENCE_LEVEL",
                ["connector", "confidence_level"],
                config,
                default=60,
            )
        )

    # ── Forescout helpers ──────────────────────────────────────────────────────

    def _iter_hosts(self):
        """Yield Forescout host dicts, paginating through the full inventory."""
        start = 0
        while True:
            data = self.session.get(
                "/api/hosts",
                params={
                    "fields": self.host_fields,
                    "count":  PAGE_SIZE,
                    "startIndex": start,
                },
            )
            hosts = data.get("hosts", [])
            if not hosts:
                break
            yield from hosts
            if len(hosts) < PAGE_SIZE:
                break
            start += PAGE_SIZE

    @staticmethod
    def _host_field(host: dict, *keys: str) -> str:
        """Extract a value from a Forescout host's `fields` dict, trying multiple keys."""
        fields = host.get("fields", {})
        for k in keys:
            v = fields.get(k)
            if v and isinstance(v, dict):
                v = v.get("value") or v.get("compositeValue", {}).get("value")
            if v and str(v).strip():
                return str(v).strip()
        return ""

    # ── CPE matching ──────────────────────────────────────────────────────────

    def _find_cpe_software(self, vendor: str, product: str, version: str) -> list[dict]:
        """
        Match a Forescout device to Software observables (CPE) already in OpenCTI.
        Uses substring contains on the CPE string — safer than exact match.
        Only matches firmware/OS CPEs (cpe:2.3:o:...) and app CPEs (cpe:2.3:a:...).
        Hardware CPEs (cpe:2.3:h:...) are NOT in OpenCTI (CPE connector skips them).
        """
        if not vendor and not product:
            return []

        v = vendor.lower().replace(" ", "_").replace("-", "_")
        p = product.lower().replace(" ", "_").replace("-", "_")
        # Take the first two significant words of the product name
        parts = [x for x in p.split("_") if x][:2]
        p = "_".join(parts)

        fragment = f":{v}:{p}:"
        if version and version not in ("*", "-", ""):
            ver = version.lower().replace(" ", "_").split()[0]  # "10.1.2 build 3" → "10.1.2"
            fragment += ver + ":"

        try:
            return self.helper.api.stix_cyber_observable.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "cpe", "values": [fragment], "operator": "contains"}],
                    "filterGroups": [],
                },
                first=10,
                customAttributes="id standard_id",
            ) or []
        except Exception as exc:
            self.helper.log_warning(f"CPE lookup failed for '{fragment}': {exc}")
            return []

    # ── STIX bundle builder ────────────────────────────────────────────────────

    def _build_host_objects(self, host: dict) -> list:
        """Return STIX objects for a single Forescout host."""
        ip_str  = host.get("ip", "")
        mac_str = host.get("mac", "")

        hostname = self._host_field(host, "hostname", "nbthost")
        vendor   = self._host_field(host, "cl_vendor", "vendor")
        product  = self._host_field(host, "cl_os")
        version  = self._host_field(host, "cl_patchlevel")
        category = self._host_field(host, "cl_category")
        model    = self._host_field(host, "cl_model")

        if not ip_str:
            return []

        objects = []

        # ── System (Identity) ────────────────────────────────────────────────
        system_name = hostname or ip_str
        system_desc_parts = [x for x in [vendor, product, version, model, category] if x]
        system_desc = " | ".join(system_desc_parts) if system_desc_parts else None

        system = stix2.Identity(
            id=PyCTIIdentity.generate_id(identity_class="system", name=system_name),
            identity_class="system",
            name=system_name,
            description=system_desc,
            confidence=self.confidence,
            object_marking_refs=[stix2.TLP_GREEN],
            allow_custom=True,
            custom_properties={"x_opencti_aliases": [ip_str] if ip_str != system_name else []},
        )
        objects.append(system)

        # ── IPv4-Addr ────────────────────────────────────────────────────────
        try:
            ipv4 = stix2.IPv4Address(
                value=ip_str,
                object_marking_refs=[stix2.TLP_GREEN],
                allow_custom=True,
            )
            objects.append(ipv4)
            objects.append(stix2.Relationship(
                id=StixCoreRelationship.generate_id("related-to", system.id, ipv4.id),
                relationship_type="related-to",
                source_ref=system.id,
                target_ref=ipv4.id,
                confidence=self.confidence,
                allow_custom=True,
                object_marking_refs=[stix2.TLP_GREEN],
            ))
        except Exception:
            pass  # invalid IP — skip

        # ── MAC-Addr ─────────────────────────────────────────────────────────
        if mac_str:
            try:
                mac = stix2.MACAddress(
                    value=mac_str,
                    object_marking_refs=[stix2.TLP_GREEN],
                    allow_custom=True,
                )
                objects.append(mac)
                objects.append(stix2.Relationship(
                    id=StixCoreRelationship.generate_id("related-to", system.id, mac.id),
                    relationship_type="related-to",
                    source_ref=system.id,
                    target_ref=mac.id,
                    confidence=self.confidence,
                    allow_custom=True,
                    object_marking_refs=[stix2.TLP_GREEN],
                ))
            except Exception:
                pass

        # ── Hostname ─────────────────────────────────────────────────────────
        if hostname and hostname != ip_str:
            try:
                host_obs = CustomObservableHostname(
                    value=hostname,
                    object_marking_refs=[stix2.TLP_GREEN],
                    allow_custom=True,
                )
                objects.append(host_obs)
                objects.append(stix2.Relationship(
                    id=StixCoreRelationship.generate_id("related-to", system.id, host_obs.id),
                    relationship_type="related-to",
                    source_ref=system.id,
                    target_ref=host_obs.id,
                    confidence=self.confidence,
                    allow_custom=True,
                    object_marking_refs=[stix2.TLP_GREEN],
                ))
            except Exception:
                pass

        # ── System → Software (CPE) ──────────────────────────────────────────
        cpe_matches = self._find_cpe_software(vendor, product, version)
        for sw in cpe_matches:
            try:
                objects.append(stix2.Relationship(
                    id=StixCoreRelationship.generate_id("related-to", system.id, sw["standard_id"]),
                    relationship_type="related-to",
                    source_ref=system.id,
                    target_ref=sw["standard_id"],
                    confidence=self.confidence,
                    allow_custom=True,
                    object_marking_refs=[stix2.TLP_GREEN],
                ))
            except Exception:
                pass

        return objects

    # ── Main processing ────────────────────────────────────────────────────────

    def _process(self, work_id: str) -> None:
        self.helper.log_info("Forescout connector run starting …")
        stats = {"hosts": 0, "objects": 0, "bundles": 0, "errors": 0, "cpe_matches": 0}
        bundle_objects: list = []

        def _flush(force: bool = False):
            if bundle_objects and (force or len(bundle_objects) >= BUNDLE_SIZE):
                bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
                self.helper.send_stix2_bundle(
                    bundle.serialize(),
                    update=True,
                    work_id=work_id,
                )
                stats["bundles"] += 1
                bundle_objects.clear()

        for host in self._iter_hosts():
            try:
                objs = self._build_host_objects(host)
                cpe_rels = sum(1 for o in objs if isinstance(o, stix2.Relationship)
                               and o.relationship_type == "related-to"
                               and any(sw in str(o.target_ref) for sw in ["software", "x-opencti"]))
                stats["hosts"] += 1
                stats["objects"] += len(objs)
                stats["cpe_matches"] += cpe_rels
                bundle_objects.extend(objs)
                _flush()
            except Exception as exc:
                self.helper.log_warning(f"Host {host.get('ip', '?')}: {exc}")
                stats["errors"] += 1

            if stats["hosts"] % 100 == 0 and stats["hosts"] > 0:
                self.helper.log_info(
                    f"  … {stats['hosts']} hosts processed | "
                    f"{stats['objects']} objects | {stats['errors']} errors"
                )

        _flush(force=True)

        self.helper.log_info(
            f"Forescout done — hosts={stats['hosts']} objects={stats['objects']} "
            f"bundles={stats['bundles']} cpe_matches={stats['cpe_matches']} "
            f"errors={stats['errors']}"
        )

    # ── Run loop ───────────────────────────────────────────────────────────────

    def run(self) -> None:
        self.helper.log_info("Forescout Asset connector starting …")
        duration_str = self.helper.connect_duration_period or "P1D"
        interval = self._parse_duration(duration_str)

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

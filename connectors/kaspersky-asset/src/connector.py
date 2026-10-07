#!/usr/bin/env python3
"""
Kaspersky Security Center Asset Connector — external-import connector for OpenCTI

Pulls the managed device inventory from KSC 15.x via the Open API (port 13299)
and creates the following OpenCTI objects per device:

    System (Identity)      ← managed endpoint
    IPv4-Addr              ← IP address

    System → related-to → IPv4-Addr
    System → related-to → Software (CPE)   ← matched against CPE observables in OpenCTI

The System → Software(CPE) → has → CVE chain (built by cve-cpe-mapper) then
exposes which CVEs affect which real assets in the OpenCTI dashboard.

Runs on the schedule defined by CONNECTOR_DURATION_PERIOD (default P1D).
"""

import base64
import socket
import struct
import time
from datetime import datetime, timezone

import requests
import stix2
import urllib3
from pycti import (
    Identity as PyCTIIdentity,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHUNK_SIZE  = 1000
BUNDLE_SIZE = 200


class KSCSession:
    """KSC Open API session — handles auth and automatic re-login on 401."""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.base_url = f"https://{host}:{port}/api/v1.0"
        self._username = username
        self._password = password
        self._session  = requests.Session()
        self._session.verify = False
        self._logged_in = False

    def _login(self) -> None:
        user_b64 = base64.b64encode(self._username.encode()).decode()
        pass_b64 = base64.b64encode(self._password.encode()).decode()
        resp = self._session.post(
            f"{self.base_url}/login",
            headers={
                "Authorization": f'KSCBasic user="{user_b64}", pass="{pass_b64}", internal="1"',
                "Content-Type": "application/json",
            },
            data="{}",
            timeout=30,
        )
        resp.raise_for_status()
        self._logged_in = True

    def post(self, method: str, body: dict, retry: bool = True) -> dict:
        if not self._logged_in:
            self._login()
        resp = self._session.post(
            f"{self.base_url}/{method}",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        if resp.status_code == 401 and retry:
            self._logged_in = False
            self._login()
            return self.post(method, body, retry=False)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def ip_from_long(n: int) -> str:
        """Decode KSC KLHST_WKS_IP_LONG (little-endian 32-bit unsigned int) to dotted-quad."""
        return socket.inet_ntoa(struct.pack("<I", n))


class KasperskyAssetConnector:
    def __init__(self, config: dict):
        self.helper = OpenCTIConnectorHelper(config)

        host     = get_config_variable("KSC_HOST",     ["ksc", "host"],     config)
        port     = int(get_config_variable("KSC_PORT", ["ksc", "port"],     config, default=13299))
        username = get_config_variable("KSC_USERNAME",  ["ksc", "username"], config)
        password = get_config_variable("KSC_PASSWORD",  ["ksc", "password"], config)

        self.ksc = KSCSession(host, port, str(username), str(password))

        self.confidence = int(get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            default=60,
        ))

    # ── KSC helpers ───────────────────────────────────────────────────────────

    def _iter_hosts(self):
        """Yield host dicts from KSC HostGroup.FindHosts via ChunkAccessor."""
        res = self.ksc.post("HostGroup.FindHosts", {
            "wstrFilter": "",
            "vecFieldsToReturn": [
                "KLHST_WKS_HOSTNAME",
                "KLHST_WKS_WINHOSTNAME",
                "KLHST_WKS_FQDN",
                "KLHST_WKS_IP_LONG",
                "KLHST_WKS_OS_NAME",
                "KLHST_WKS_OS_VER_MAJOR",
                "KLHST_WKS_OS_VER_MINOR",
            ],
            "vecFieldsToOrder": [],
            "pParams": {},
            "lMaxLifeTime": 600,
        })
        accessor    = res["strAccessor"]
        total_count = res.get("PxgRetVal", 0)
        self.helper.log_info(f"KSC reported {total_count} managed hosts")

        start = 0
        while True:
            chunk_res = self.ksc.post("ChunkAccessor.GetItemsChunk", {
                "strAccessor": accessor,
                "nStart":      start,
                "nCount":      CHUNK_SIZE,
            })
            items = chunk_res.get("pChunk", {}).get("KLCSP_ITERATOR_ARRAY", [])
            if not items:
                break
            for item in items:
                yield item.get("value", {})
            if len(items) < CHUNK_SIZE:
                break
            start += CHUNK_SIZE

    def _get_host_software(self, host_guid: str) -> list[dict]:
        """Return installed apps for a host via InventoryApi.GetHostInvProducts."""
        try:
            res = self.ksc.post("InventoryApi.GetHostInvProducts", {
                "szwHostId": host_guid,
            })
            entries = res.get("PxgRetVal", {}).get("GNRL_EA_PARAM_1", [])
            return [e.get("value", {}) for e in entries if isinstance(e, dict)]
        except Exception as exc:
            self.helper.log_warning(f"GetHostInvProducts failed for {host_guid}: {exc}")
            return []

    # ── CPE matching ──────────────────────────────────────────────────────────

    def _find_cpe_software(self, vendor: str, product: str, version: str) -> list[dict]:
        """
        Match a KSC app (Publisher, DisplayName, DisplayVersion) to Software
        observables (CPE strings) already in OpenCTI via substring contains.
        Only matches firmware/OS CPEs (cpe:2.3:o:...) and app CPEs (cpe:2.3:a:...).
        """
        if not vendor and not product:
            return []

        v = vendor.lower().replace(" ", "_").replace("-", "_")
        p = product.lower().replace(" ", "_").replace("-", "_")
        parts = [x for x in p.split("_") if x][:2]
        p = "_".join(parts)

        fragment = f":{v}:{p}:"
        if version and version not in ("*", "-", ""):
            ver = version.lower().replace(" ", "_").split()[0]
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

    # ── STIX bundle builder ───────────────────────────────────────────────────

    def _build_host_objects(self, host: dict) -> list:
        """Return STIX objects for a single KSC-managed host."""
        host_guid = host.get("KLHST_WKS_HOSTNAME", "")
        if not host_guid:
            return []

        hostname  = host.get("KLHST_WKS_FQDN") or host.get("KLHST_WKS_WINHOSTNAME", "")
        os_name   = host.get("KLHST_WKS_OS_NAME", "")
        ip_long   = host.get("KLHST_WKS_IP_LONG")

        ip_str = ""
        if ip_long:
            try:
                ip_str = KSCSession.ip_from_long(ip_long)
            except Exception:
                pass

        system_name = hostname or ip_str or host_guid
        objects = []

        # ── System (Identity) ────────────────────────────────────────────────
        system = stix2.Identity(
            id=PyCTIIdentity.generate_id(identity_class="system", name=system_name),
            identity_class="system",
            name=system_name,
            description=os_name or None,
            confidence=self.confidence,
            object_marking_refs=[stix2.TLP_GREEN],
            allow_custom=True,
            custom_properties={"x_opencti_aliases": [ip_str] if ip_str and ip_str != system_name else []},
        )
        objects.append(system)

        # ── IPv4-Addr ────────────────────────────────────────────────────────
        if ip_str:
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
                pass

        # ── Software (CPE) matching ──────────────────────────────────────────
        apps = self._get_host_software(host_guid)
        matched_cpes: set[str] = set()

        for app in apps:
            vendor  = app.get("Publisher", "")
            product = app.get("DisplayName", "")
            version = app.get("DisplayVersion", "")

            if not vendor or not product:
                continue

            cpe_matches = self._find_cpe_software(vendor, product, version)
            for sw in cpe_matches:
                std_id = sw.get("standard_id")
                if not std_id or std_id in matched_cpes:
                    continue
                matched_cpes.add(std_id)
                try:
                    objects.append(stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", system.id, std_id),
                        relationship_type="related-to",
                        source_ref=system.id,
                        target_ref=std_id,
                        confidence=self.confidence,
                        allow_custom=True,
                        object_marking_refs=[stix2.TLP_GREEN],
                    ))
                except Exception:
                    pass

        return objects

    # ── Main processing ───────────────────────────────────────────────────────

    def _process(self, work_id: str) -> None:
        self.helper.log_info("KSC asset connector run starting …")
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
                cpe_count = sum(
                    1 for o in objs
                    if isinstance(o, stix2.Relationship)
                    and o.relationship_type == "related-to"
                )
                stats["hosts"]      += 1
                stats["objects"]    += len(objs)
                stats["cpe_matches"] += max(0, cpe_count - 1)  # exclude the IP rel
                bundle_objects.extend(objs)
                _flush()
            except Exception as exc:
                self.helper.log_warning(
                    f"Host {host.get('KLHST_WKS_WINHOSTNAME', host.get('KLHST_WKS_HOSTNAME', '?'))}: {exc}"
                )
                stats["errors"] += 1

            if stats["hosts"] % 50 == 0 and stats["hosts"] > 0:
                self.helper.log_info(
                    f"  … {stats['hosts']} hosts | {stats['objects']} objects | "
                    f"{stats['cpe_matches']} CPE matches | {stats['errors']} errors"
                )

        _flush(force=True)
        self.helper.log_info(
            f"KSC done — hosts={stats['hosts']} objects={stats['objects']} "
            f"bundles={stats['bundles']} cpe_matches={stats['cpe_matches']} "
            f"errors={stats['errors']}"
        )

    # ── Run loop ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        self.helper.log_info("Kaspersky Asset connector starting …")
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

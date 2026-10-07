#!/usr/bin/env python3
"""
Debug: collect all unique host GUIDs from the vuln view (including offline/historical),
then query per-GUID to get the full dataset past the 10k cap.
"""
import base64
import os
import requests
import urllib3

urllib3.disable_warnings()

KSC_HOST     = os.environ["KSC_HOST"]
KSC_PORT     = int(os.environ.get("KSC_PORT", "13299"))
KSC_USERNAME = os.environ["KSC_USERNAME"]
KSC_PASSWORD = os.environ["KSC_PASSWORD"]

base_url = f"https://{KSC_HOST}:{KSC_PORT}/api/v1.0"
s = requests.Session()
s.verify = False

u = base64.b64encode(KSC_USERNAME.encode()).decode()
p = base64.b64encode(KSC_PASSWORD.encode()).decode()

print("Logging in ...")
r = s.post(f"{base_url}/login", headers={
    "Authorization": f'KSCBasic user="{u}", pass="{p}", internal="1"',
    "Content-Type": "application/json",
}, data="{}")
r.raise_for_status()
print("Login OK\n")


def srvview_fetch(filter_str="", fields=None):
    """Fetch all rows from v_vapm_vulnerability with optional filter."""
    if fields is None:
        fields = ["VulnerabilityId", "KLHST_WKS_HOSTNAME"]
    r = s.post(f"{base_url}/SrvView.ResetIterator", json={
        "wstrViewName":      "v_vapm_vulnerability",
        "wstrFilter":        filter_str,
        "vecFieldsToReturn": fields,
        "vecFieldsToOrder":  [],
        "lifetimeSec":       300,
    }, headers={"Content-Type": "application/json"})
    res = r.json()
    if "PxgError" in res:
        print(f"  SrvView error: {res['PxgError']}")
        return []
    it = res["wstrIteratorId"]
    total = s.post(f"{base_url}/SrvView.GetRecordCount",
                   json={"wstrIteratorId": it},
                   headers={"Content-Type": "application/json"}).json().get("PxgRetVal", 0)
    rows = []
    start = 0
    PAGE = 1000
    while start < total:
        end = min(start + PAGE, total)
        chunk = s.post(f"{base_url}/SrvView.GetRecordRange", json={
            "wstrIteratorId": it, "nStart": start, "nEnd": end,
        }, headers={"Content-Type": "application/json"})
        items = chunk.json().get("pRecords", {}).get("KLCSP_ITERATOR_ARRAY", [])
        for item in items:
            rows.append(item.get("value", {}))
        if len(items) < (end - start):
            break
        start = end
    s.post(f"{base_url}/SrvView.ReleaseIterator",
           json={"wstrIteratorId": it},
           headers={"Content-Type": "application/json"})
    return rows


# ── Step 1: get all GUIDs from FindHosts ─────────────────────────────────────
print("Fetching host GUIDs from FindHosts ...")
r = s.post(f"{base_url}/HostGroup.FindHosts", json={
    "wstrFilter":        "",
    "vecFieldsToReturn": ["KLHST_WKS_HOSTNAME", "KLHST_WKS_DN"],
    "vecFieldsToOrder":  [],
    "lMaxLifeTime":      120,
}, headers={"Content-Type": "application/json"})
res = r.json()
accessor = res["strAccessor"]
total_hosts = res.get("PxgRetVal", 0)

host_map = {}  # guid → dn
start = 0
while True:
    chunk = s.post(f"{base_url}/ChunkAccessor.GetItemsChunk", json={
        "strAccessor": accessor, "nStart": start, "nCount": 500,
    }, headers={"Content-Type": "application/json"})
    items = chunk.json().get("pChunk", {}).get("KLCSP_ITERATOR_ARRAY", [])
    if not items:
        break
    for item in items:
        v = item.get("value", {})
        guid = v.get("KLHST_WKS_HOSTNAME", "")
        if guid:
            host_map[guid] = v.get("KLHST_WKS_DN", guid)
    if len(items) < 500:
        break
    start += len(items)

print(f"FindHosts: {len(host_map)} hosts\n")

# ── Step 2: get all GUIDs from the vuln view (global, capped) ─────────────────
print("Fetching GUIDs from vuln view (global, capped at ~10k) ...")
global_rows = srvview_fetch(fields=["KLHST_WKS_HOSTNAME"])
view_guids = {r.get("KLHST_WKS_HOSTNAME", "") for r in global_rows} - {""}
print(f"Unique GUIDs in global view: {len(view_guids)}")

extra_guids = view_guids - set(host_map.keys())
print(f"GUIDs in view but NOT in FindHosts (offline/historical): {len(extra_guids)}\n")

# All GUIDs to process
all_guids = set(host_map.keys()) | extra_guids

# ── Step 3: count per-GUID ────────────────────────────────────────────────────
print(f"Counting vulns per host GUID ({len(all_guids)} total) ...")
grand_total = 0
hosts_with_vulns = 0

for guid in sorted(all_guids):
    rows = srvview_fetch(
        filter_str=f'KLHST_WKS_HOSTNAME = "{guid}"',
        fields=["VulnerabilityId"],
    )
    n = len(rows)
    if n > 0:
        dn = host_map.get(guid, "(offline/historical)")
        print(f"  {dn:35s}  {n:>5} vulns")
        grand_total += n
        hosts_with_vulns += 1

print(f"\nHosts with vulns: {hosts_with_vulns}")
print(f"Grand total vuln rows (per-GUID sum): {grand_total}")
print(f"Global iterator showed:               {len(global_rows)} (capped)")
print(f"Gap: {grand_total - len(global_rows)} rows recovered by per-GUID approach")

#!/usr/bin/env python3
"""
DGSSI bulletin scraper.

Fetches the bulletin listing from dgssi.gov.ma and parses individual bulletin
pages into structured dicts. Two bulletin types are handled:
  - Vulnerability bulletins: have CVE identifiers and affected systems
  - Threat/malware bulletins: have IOCs (hashes, IPs) and malware names
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from bs4 import BeautifulSoup

BASE_URL      = "https://www.dgssi.gov.ma"
LIST_URL      = f"{BASE_URL}/fr/bulletins/"
REQUEST_DELAY = 0.3   # seconds between requests

# Section heading keywords (all lowercase)
_HEADING_TAGS = ["h1", "h2", "h3", "h4", "h5", "strong", "b"]


@dataclass
class DgssiBulletin:
    reference: str
    title: str
    url: str
    published: str              # ISO date string YYYY-MM-DD
    risk_level: str             # Critique / Important / Modéré / Faible
    impact_level: str
    bilan: str
    affected_systems: list[str]  = field(default_factory=list)
    cve_ids: list[str]           = field(default_factory=list)
    risks: list[str]             = field(default_factory=list)
    solution: str                = ""
    reference_urls: list[str]    = field(default_factory=list)
    pdf_url: Optional[str]       = None
    # malware/threat fields
    malware_names: list[str]     = field(default_factory=list)
    ioc_hashes: list[str]        = field(default_factory=list)
    ioc_ips: list[str]           = field(default_factory=list)


def _get(url: str, session: requests.Session) -> Optional[BeautifulSoup]:
    url = url.replace("http://", "https://", 1)
    if not url.endswith("/"):
        url = url + "/"
    try:
        resp = session.get(url, timeout=10, allow_redirects=False)
        # Follow redirects manually, forcing https on every hop
        while resp.is_redirect:
            location = resp.headers.get("Location", "")
            location = location.replace("http://", "https://", 1)
            resp = session.get(location, timeout=10, allow_redirects=False)
        resp.raise_for_status()
        resp.encoding = "utf-8"
        return BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        print(f"[DGSSI scraper] ERROR fetching {url}: {type(e).__name__}: {e}", flush=True)
        return None
    finally:
        time.sleep(REQUEST_DELAY)


def _text(el) -> str:
    if not el:
        return ""
    return el.get_text(separator=" ", strip=True).replace("\xa0", " ").replace(";", "").strip()


def _parse_date(raw: str) -> str:
    """Convert French date like '14 mai 2026' to '2026-05-14'."""
    months = {
        "janvier": "01", "février": "02", "mars": "03", "avril": "04",
        "mai": "05", "juin": "06", "juillet": "07", "août": "08",
        "septembre": "09", "octobre": "10", "novembre": "11", "décembre": "12",
    }
    raw = raw.strip().lower()
    m = re.match(r"(\d{1,2})\s+(\w+)\s+(\d{4})", raw)
    if not m:
        return raw
    day, month_fr, year = m.groups()
    month = months.get(month_fr, "01")
    return f"{year}-{month}-{int(day):02d}"


def _extract_cves(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))


def _extract_hashes(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\b[0-9a-fA-F]{64}\b", text)))


def _extract_ips(text: str) -> list[str]:
    # Match only dotted-quad patterns not preceded or followed by a dot or digit
    # (avoids version strings like 25.07.21.01 embedded in longer sequences)
    candidates = re.findall(r"(?<![.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![.\d])", text)
    valid = []
    seen: set[str] = set()
    for ip in candidates:
        if ip in seen:
            continue
        parts = ip.split(".")
        # All octets must be valid (0-255) and none zero-padded (e.g. "01")
        if all(p == str(int(p)) and 0 <= int(p) <= 255 for p in parts):
            seen.add(ip)
            valid.append(ip)
    return valid


def _extract_pdf(soup: BeautifulSoup) -> Optional[str]:
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.lower().endswith(".pdf"):
            if href.startswith("http"):
                return href.replace("http://", "https://", 1)
            return BASE_URL + href
    return None


def _find_section(soup: BeautifulSoup, keywords: list[str]):
    """Return the heading tag whose text contains any of the keywords."""
    for tag in soup.find_all(_HEADING_TAGS):
        t = _text(tag).lower()
        if any(k in t for k in keywords):
            return tag
    return None


def _section_text(soup: BeautifulSoup, keywords: list[str]) -> str:
    heading = _find_section(soup, keywords)
    if not heading:
        return ""
    # Prefer field__item div siblings (Drupal pattern) — excludes the heading itself
    parts = []
    for sib in heading.next_siblings:
        if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
            break
        if hasattr(sib, "find"):
            item = sib.find(class_="field__item")
            if item:
                parts.append(_text(item))
                continue
        t = _text(sib) if hasattr(sib, "get_text") else str(sib).strip()
        if t:
            parts.append(t)
    if not parts:
        for sib in heading.parent.next_siblings:
            if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
                break
            if hasattr(sib, "find"):
                item = sib.find(class_="field__item")
                if item:
                    parts.append(_text(item))
                    continue
            t = _text(sib) if hasattr(sib, "get_text") else str(sib).strip()
            if t:
                parts.append(t)
    return " ".join(parts).strip()


def _section_list(soup: BeautifulSoup, keywords: list[str]) -> list[str]:
    heading = _find_section(soup, keywords)
    if not heading:
        return []
    items = []
    # Search siblings of heading and of its parent
    for container in [heading, heading.parent]:
        for sib in container.next_siblings:
            if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
                break
            if hasattr(sib, "find_all"):
                for li in sib.find_all("li"):
                    t = _text(li)
                    if t:
                        items.append(t)
        if items:
            break
    return items


def _section_html(soup: BeautifulSoup, keywords: list[str]) -> str:
    """Return the inner HTML of the section as a string for rich rendering."""
    heading = _find_section(soup, keywords)
    if not heading:
        return ""
    parts = []
    for sib in heading.next_siblings:
        if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
            break
        if hasattr(sib, "decode"):
            parts.append(str(sib))
    if not parts:
        for sib in heading.parent.next_siblings:
            if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
                break
            if hasattr(sib, "decode"):
                parts.append(str(sib))
    return "".join(parts).strip()


def _parse_bulletin_page(url: str, soup: BeautifulSoup) -> DgssiBulletin:
    full_text = soup.get_text(separator="\n")

    # ── metadata table ────────────────────────────────────────────────────────
    # Table cells contain the label text inside the value cell too (Drupal rendering),
    # so we strip the label from the value.
    reference = title = published = risk_level = impact_level = ""
    for row in soup.select("table tr"):
        cells = row.find_all(["td", "th"])
        if len(cells) < 2:
            continue
        label = _text(cells[0]).lower()
        # Strip the repeated label from the value cell
        value = _text(cells[1])
        value = re.sub(r"^" + re.escape(_text(cells[0])), "", value).strip()

        if "référence" in label and "titre" not in label:
            reference = value
        elif "titre" in label:
            title = value
        elif "publication" in label:
            published = _parse_date(value)
        elif "risque" in label:
            risk_level = value
        elif "impact" in label:
            impact_level = value

    if not title:
        h1 = soup.find("h1")
        title = _text(h1) if h1 else url.rstrip("/").split("/")[-1].replace("-", " ").title()

    # ── sections ──────────────────────────────────────────────────────────────
    bilan            = _section_text(soup, ["bilan", "description", "résumé"])
    solution         = _section_text(soup, ["solution", "recommandation", "mesure"])
    affected_systems = _section_list(soup, ["systèmes affectés", "systèmes concernés", "produits affectés"])
    risks            = _section_list(soup, ["risque"])

    # ── CVEs ──────────────────────────────────────────────────────────────────
    cve_ids: list[str] = []
    heading = _find_section(soup, ["identificateur", "externe"])
    if heading:
        raw = _text(heading.parent)
        for sib in heading.parent.next_siblings:
            if hasattr(sib, "get_text"):
                raw += " " + sib.get_text()
            if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
                break
        cve_ids = _extract_cves(raw)
    if not cve_ids:
        cve_ids = _extract_cves(full_text)

    # ── external reference URLs ───────────────────────────────────────────────
    reference_urls: list[str] = []
    ref_heading = _find_section(soup, ["référence"])
    if ref_heading:
        for sib in ref_heading.next_siblings:
            if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
                break
            if hasattr(sib, "find_all"):
                for a in sib.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("http") and not href.endswith(".pdf"):
                        reference_urls.append(href)
        if not reference_urls:
            for sib in ref_heading.parent.next_siblings:
                if hasattr(sib, "name") and sib.name in _HEADING_TAGS:
                    break
                if hasattr(sib, "find_all"):
                    for a in sib.find_all("a", href=True):
                        href = a["href"]
                        if href.startswith("http") and not href.endswith(".pdf"):
                            reference_urls.append(href)

    # ── IOCs (malware bulletins) ──────────────────────────────────────────────
    ioc_hashes = _extract_hashes(full_text)
    ioc_ips    = _extract_ips(full_text)

    # ── malware names ─────────────────────────────────────────────────────────
    malware_names: list[str] = []
    m = re.search(r'["“]([^"”]{3,40})["”]\s*(malware|trojan|ransomware|virus|worm|botnet)',
                  full_text, re.IGNORECASE)
    if m:
        malware_names.append(m.group(1).strip())

    pdf_url = _extract_pdf(soup)

    return DgssiBulletin(
        reference=reference,
        title=title,
        url=url,
        published=published,
        risk_level=risk_level,
        impact_level=impact_level,
        bilan=bilan,
        affected_systems=affected_systems,
        cve_ids=cve_ids,
        risks=risks,
        solution=solution,
        reference_urls=reference_urls,
        pdf_url=pdf_url,
        malware_names=malware_names,
        ioc_hashes=ioc_hashes,
        ioc_ips=ioc_ips,
    )


def fetch_bulletin_urls(session: requests.Session) -> list[str]:
    """Return bulletin detail page URLs from the listing, newest first."""
    soup = _get(LIST_URL, session)
    if not soup:
        return []

    seen: set[str] = set()
    urls: list[str] = []
    list_path = "/fr/bulletins/"

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if list_path not in href:
            continue
        slug = href.split(list_path)[-1].strip("/")
        if not slug:
            continue
        full = href.rstrip("/") if href.startswith("http") else BASE_URL + list_path + slug
        full = full.replace("http://", "https://", 1)
        if full not in seen:
            seen.add(full)
            urls.append(full)

    return urls


def fetch_bulletin(url: str, session: requests.Session) -> Optional[DgssiBulletin]:
    soup = _get(url, session)
    if not soup:
        return None
    return _parse_bulletin_page(url, soup)

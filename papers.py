#!/usr/bin/env python3
"""Fetch new systems/security papers into data/papers.json for the web feed."""

import html
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from defusedxml import ElementTree as ET

try:
    import certifi

    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "papers.json")
UA = "wiredIn-paperfeed/1.0 (+https://github.com/fr4nsyz/wiredIn)"

ARXIV_CATEGORIES = ["cs.CR", "cs.OS", "cs.DC", "cs.AR"]
ARXIV_PER_QUERY = 200
# arXiv papers matching these are kept forever; the rest expire after ARXIV_RETENTION_DAYS.
KEYWORDS = ["eBPF", "EDR", "endpoint detection", "silent data corruption", "fuzz"]
ARXIV_RETENTION_DAYS = 45

USENIX_CONFS = {"usenix-security": ("usenixsecurity", "USENIX Security"), "osdi": ("osdi", "OSDI")}
S2_VENUES = {"ccs": "Conference on Computer and Communications Security"}
VENUE_YEARS_BACK = 1
ABSTRACT_MAX = 1500
ATOM = "{http://www.w3.org/2005/Atom}"
ARXIV_NS = "{http://arxiv.org/schemas/atom}"
TOP_VENUES = [
    ("OSDI", r"\bOSDI\b|Operating Systems Design and Implementation"),
    ("SOSP", r"\bSOSP\b|Symposium on Operating Systems Principles"),
    ("USENIX Security", r"USENIX Security|\bSEC ?'?\d\d\b"),
    ("CCS", r"(?<!Asia)(?<!Asia )\bCCS\b|Computer and Communications Security"),
    ("IEEE S&P", r"\bS&P\b|\bS&amp;P\b|Oakland|Symposium on Security and Privacy"),
    ("NDSS", r"\bNDSS\b"),
    ("NSDI", r"\bNSDI\b"),
    ("EuroSys", r"\bEuroSys\b"),
    ("ASPLOS", r"\bASPLOS\b"),
    ("USENIX ATC", r"\bUSENIX ATC\b|Annual Technical Conference"),
    ("MLSys", r"\bMLSys\b"),
    ("ISCA", r"\bISCA\b"),
    ("MICRO", r"\bMICRO\b"),
]
NOT_ACCEPTED = re.compile(
    r"submit|under review|in review|rejected|workshop|co-located|in conjunction|poster|competition|\bSPW\b|'\d\d at ",
    re.I,
)
YEAR = re.compile(r"\b20(\d\d)\b|'(\d\d)\b|(?:S&P|SEC) (\d\d)\b")
# Semantic Scholar lists posters, demos and workshop front matter under the main venue.
NOT_A_PAPER = re.compile(r"^(Poster|Demo|Demonstration|Invited Talk|Keynote|Tutorial|Panel)\b|\bWorkshop\b|'\d\d: ", re.I)


def get(url, headers=None, tries=6):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60, context=SSL_CTX) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == tries - 1:
                raise
        time.sleep(5 * 2**attempt)


def clean(s):
    return re.sub(r"\s+", " ", s or "").strip()


def keyword_hit(text):
    t = text.lower()
    return any(re.search(r"(?<![a-z0-9])" + re.escape(k.lower()), t) for k in KEYWORDS)


def accepted_at(*fields):
    """Top venue an arXiv paper's comment/journal_ref says it was accepted at, or None."""
    text = " ".join(f for f in fields if f)
    if not text or NOT_ACCEPTED.search(text):
        return None
    years = [int(next(g for g in m.groups() if g)) for m in YEAR.finditer(text)]
    if years and 2000 + max(years) < datetime.now(timezone.utc).year - 1:
        return None
    for name, pat in TOP_VENUES:
        if re.search(pat, text):
            return name
    return None


def fetch_arxiv_query(query):
    params = urllib.parse.urlencode(
        {
            "search_query": query,
            "sortBy": "submittedDate",
            "sortOrder": "descending",
            "max_results": ARXIV_PER_QUERY,
        }
    )
    root = ET.fromstring(get("https://export.arxiv.org/api/query?" + params))
    out = []
    for e in root.findall(ATOM + "entry"):
        abs_url = e.findtext(ATOM + "id", "")
        m = re.search(r"abs/([^v]+)", abs_url)
        if not m:
            continue
        aid = m.group(1)
        cats = [c.get("term") for c in e.findall(ATOM + "category")]
        accepted = accepted_at(e.findtext(ARXIV_NS + "comment"), e.findtext(ARXIV_NS + "journal_ref"))
        out.append(
            {
                "id": "arxiv:" + aid,
                "source": "arxiv",
                "venue": "arXiv " + (cats[0] if cats else ""),
                "title": clean(e.findtext(ATOM + "title")),
                "authors": [clean(a.findtext(ATOM + "name")) for a in e.findall(ATOM + "author")],
                "abstract": clean(e.findtext(ATOM + "summary"))[:ABSTRACT_MAX],
                "date": (e.findtext(ATOM + "published") or "")[:10],
                "url": "https://arxiv.org/abs/" + aid,
                "pdf": "https://arxiv.org/pdf/" + aid,
                "accepted": accepted,
            }
        )
    return out


def fetch_arxiv():
    kw = " OR ".join('all:"%s"' % k if " " in k else "all:" + k for k in KEYWORDS)
    queries = ["cat:" + c for c in ARXIV_CATEGORIES] + [kw]
    papers = []
    for i, q in enumerate(queries):
        if i:
            time.sleep(3)
        try:
            papers += fetch_arxiv_query(q)
        except Exception as e:
            print(f"arxiv {q}: {e}", file=sys.stderr)
    return papers


def strip_tags(s):
    return clean(html.unescape(re.sub(r"<[^>]+>", " ", s)))


def fetch_usenix(key, slug, name, year):
    conf = f"{slug}{year % 100:02d}"
    try:
        page = get(f"https://www.usenix.org/conference/{conf}/technical-sessions").decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise
    papers = []
    for block in page.split('class="node node-paper')[1:]:
        m = re.search(r'<h2>\s*<a href="(/conference/[^"]+/presentation/[^"]+)">(.*?)</a>', block, re.S)
        people = re.search(r"field-paper-people-text.*?<p>(.*?)</p>", block, re.S)
        if not m or not people:
            continue
        names = re.sub(r"<em>.*?</em>", "", people.group(1), flags=re.S)
        authors = [a for a in (clean(x) for x in re.split(r"[,;]|\band\b", strip_tags(names))) if a]
        desc = re.search(r'field-paper-description-long[^>]*>(.*?)</div>', block, re.S)
        papers.append(
            {
                "id": "usenix:" + m.group(1),
                "source": key,
                "venue": f"{name} {year}",
                "title": strip_tags(m.group(2)),
                "authors": authors,
                "abstract": strip_tags(desc.group(1))[:ABSTRACT_MAX] if desc else "",
                "date": str(year),
                "url": "https://www.usenix.org" + m.group(1),
            }
        )
    return papers


def fetch_s2_venue(key, venue):
    headers = {}
    if os.environ.get("S2_API_KEY"):
        headers["x-api-key"] = os.environ["S2_API_KEY"]
    year = datetime.now(timezone.utc).year - VENUE_YEARS_BACK
    params = {
        "query": "*",
        "venue": venue,
        "year": f"{year}-",
        "fields": "title,abstract,authors,venue,publicationDate,year,url,externalIds",
        "sort": "publicationDate:desc",
    }
    papers, token = [], None
    while True:
        if token:
            params["token"] = token
        url = "https://api.semanticscholar.org/graph/v1/paper/search/bulk?" + urllib.parse.urlencode(params)
        d = json.loads(get(url, headers))
        for p in d.get("data", []):
            if NOT_A_PAPER.search(p.get("title") or ""):
                continue
            doi = (p.get("externalIds") or {}).get("DOI")
            papers.append(
                {
                    "id": "s2:" + p["paperId"],
                    "source": key,
                    "venue": f"{p.get('venue') or venue} {p.get('year') or ''}".strip(),
                    "title": clean(p.get("title")),
                    "authors": [a.get("name", "") for a in p.get("authors") or []],
                    "abstract": clean(p.get("abstract"))[:ABSTRACT_MAX],
                    "date": p.get("publicationDate") or str(p.get("year") or ""),
                    "url": f"https://doi.org/{doi}" if doi else p.get("url"),
                }
            )
        token = d.get("token")
        if not token:
            return papers
        time.sleep(2)


def main():
    try:
        with open(OUT) as f:
            existing = {p["id"]: p for p in json.load(f)["papers"]}
    except FileNotFoundError:
        existing = {}

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    fetched = fetch_arxiv()
    for key, (slug, name) in USENIX_CONFS.items():
        for year in range(now.year - VENUE_YEARS_BACK, now.year + 2):
            try:
                fetched += fetch_usenix(key, slug, name, year)
            except Exception as e:
                print(f"usenix {slug}{year}: {e}", file=sys.stderr)
    for key, venue in S2_VENUES.items():
        try:
            fetched += fetch_s2_venue(key, venue)
        except Exception as e:
            print(f"s2 {key}: {e}", file=sys.stderr)

    if not fetched:
        sys.exit("no papers fetched from any source")

    for p in fetched:
        if not p["title"]:
            continue
        prev = existing.get(p["id"])
        p["first_seen"] = prev["first_seen"] if prev else stamp
        existing[p["id"]] = p

    cutoff = (now - timedelta(days=ARXIV_RETENTION_DAYS)).strftime("%Y-%m-%d")
    papers = [
        p
        for p in existing.values()
        if p["source"] != "arxiv" or p["date"] >= cutoff or keyword_hit(p["title"] + " " + p["abstract"])
    ]
    papers.sort(key=lambda p: (p["first_seen"], p["date"]), reverse=True)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump({"updated": stamp, "papers": papers}, f, separators=(",", ":"), ensure_ascii=False)
    added = sum(p["first_seen"] == stamp for p in papers)
    print(f"{len(papers)} papers ({added} new) -> {OUT}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
wiredIn - terminal security intelligence aggregator

Pulls the latest from top cybersecurity and systems security feeds,
displays a dense, technically-focused briefing in your terminal.

Usage:
    wiredIn                          daily brief
    wiredIn --limit 30               show more
    wiredIn --source krebs,thn       filter sources
    wiredIn --search "salt typhoon"  search
    wiredIn --tag linux              filter by tag
    wiredIn --cve                    show only articles with CVEs
    wiredIn --event defcon           conference mode
    wiredIn --ai                     AI summaries (needs Ollama or WIREDIN_API_KEY)
    wiredIn --intel                  structured threat intel format
    wiredIn --deep                   full article details
    wiredIn --export                 markdown export
    wiredIn --json                   JSON output
    wiredIn --list                   list all sources/tags/events
"""

import argparse
import sys
import json
import ssl
import os
import textwrap
import re
import hashlib
import pickle
import time
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
from collections import Counter

try:
    import defusedxml.ElementTree as ET
except ImportError:
    print(
        "WARNING: defusedxml not installed. Install it:\n  pip install defusedxml",
        file=sys.stderr,
    )
    import xml.etree.ElementTree as ET

SSL_CTX = None
try:
    import certifi

    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BLUE = "\033[34m"
WHITE = "\033[97m"
ORANGE = "\033[38;5;208m"
PINK = "\033[38;5;205m"
TEAL = "\033[38;5;36m"

FEEDS = {
    "thn": {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "color": CYAN,
        "icon": "◆",
        "type": "news",
    },
    "krebs": {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "color": RED,
        "icon": "◆",
        "type": "analysis",
    },
    "darkread": {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "color": MAGENTA,
        "icon": "◆",
        "type": "news",
    },
    "secweek": {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/securityweek",
        "color": BLUE,
        "icon": "◆",
        "type": "news",
    },
    "bleeping": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "color": GREEN,
        "icon": "◆",
        "type": "news",
    },
    "schneier": {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
        "color": YELLOW,
        "icon": "◈",
        "type": "analysis",
    },
    "helpnet": {
        "name": "Help Net Security",
        "url": "https://www.helpnetsecurity.com/feed/",
        "color": WHITE,
        "icon": "◆",
        "type": "news",
    },
    "therecord": {
        "name": "The Record",
        "url": "https://therecord.media/feed/",
        "color": TEAL,
        "icon": "◆",
        "type": "news",
    },
    "talos": {
        "name": "Talos Intelligence",
        "url": "https://blog.talosintelligence.com/feed/",
        "color": ORANGE,
        "icon": "◈",
        "type": "research",
    },
    "unit42": {
        "name": "Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "color": BLUE,
        "icon": "◈",
        "type": "research",
    },
    "sans": {
        "name": "SANS ISC Diary",
        "url": "https://isc.sans.edu/rssfeed.xml",
        "color": GREEN,
        "icon": "◈",
        "type": "ops",
    },
    "sentinel": {
        "name": "SentinelOne",
        "url": "https://www.sentinelone.com/blog/feed/",
        "color": PINK,
        "icon": "◈",
        "type": "research",
    },
    "lwnkernel": {
        "name": "LWN Kernel Security",
        "url": "https://lwn.net/headlines/rss",
        "color": CYAN,
        "icon": "⚙",
        "type": "development",
    },
    "archsec": {
        "name": "Arch Linux Security",
        "url": "https://security.archlinux.org/advisory/feed.atom",
        "color": TEAL,
        "icon": "⚙",
        "type": "advisory",
    },
    "redhat": {
        "name": "Red Hat Security",
        "url": "https://www.redhat.com/en/rss/security",
        "color": RED,
        "icon": "⚙",
        "type": "advisory",
    },
    "ubuntusec": {
        "name": "Ubuntu Security",
        "url": "https://usn.ubuntu.com/usn/atom.xml",
        "color": ORANGE,
        "icon": "⚙",
        "type": "advisory",
    },
    "debiansec": {
        "name": "Debian Security",
        "url": "https://www.debian.org/security/dsa",
        "color": PINK,
        "icon": "⚙",
        "type": "advisory",
    },
    "freebsdsec": {
        "name": "FreeBSD Security",
        "url": "https://www.freebsd.org/security/feed.xml",
        "color": RED,
        "icon": "⚙",
        "type": "advisory",
    },
    "msrc": {
        "name": "Microsoft Security",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "color": CYAN,
        "icon": "⚙",
        "type": "news",
    },
    "exploitdb": {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "color": GREEN,
        "icon": "⬡",
        "type": "exploit",
    },
    "cisa": {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
        "color": RED,
        "icon": "⚡",
        "type": "advisory",
    },
    "checkpoint": {
        "name": "Check Point Research",
        "url": "https://research.checkpoint.com/feed/",
        "color": ORANGE,
        "icon": "◈",
        "type": "research",
    },
    "portswigger": {
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss",
        "color": MAGENTA,
        "icon": "◈",
        "type": "research",
    },
    "golangsec": {
        "name": "Go Blog",
        "url": "https://go.dev/blog/feed.atom",
        "color": CYAN,
        "icon": "⚙",
        "type": "development",
    },
    "rustsec": {
        "name": "Rust Blog",
        "url": "https://blog.rust-lang.org/feed.xml",
        "color": MAGENTA,
        "icon": "⚙",
        "type": "development",
    },
    "cloudflare": {
        "name": "Cloudflare Blog",
        "url": "https://blog.cloudflare.com/rss/",
        "color": ORANGE,
        "icon": "◈",
        "type": "research",
    },
    "falco": {
        "name": "Falco Security",
        "url": "https://falco.org/feed.xml",
        "color": TEAL,
        "icon": "◈",
        "type": "development",
    },
}

EVENTS = {
    "rsac": {
        "name": "RSAC",
        "keywords": ["rsac", "rsa conference", "moscone", "innovation sandbox"],
        "color": CYAN,
    },
    "defcon": {
        "name": "DEF CON",
        "keywords": ["defcon", "def con", "hacker summer camp", "dc-"],
        "color": GREEN,
    },
    "blackhat": {
        "name": "Black Hat",
        "keywords": ["black hat", "blackhat", "bh usa", "arsenal"],
        "color": RED,
    },
    "bsides": {
        "name": "BSides",
        "keywords": ["bsides", "b-sides", "security bsides"],
        "color": YELLOW,
    },
}

THREAT_TAGS = {
    "kernel": {
        "kw": [
            "kernel",
            "kexec",
            "kasan",
            "kvm",
            "hypervisor",
            "syscall",
            "ring0",
            "ring 0",
            "kernel-space",
            "kernel space",
            "rootkit",
        ],
        "color": CYAN,
    },
    "ebpf": {"kw": ["ebpf", "bpf", "bpf()", "bpftrace", "bpfilter"], "color": TEAL},
    "edr": {
        "kw": ["edr", "endpoint detection", "endpoint security", "xdr", "mdr"],
        "color": GREEN,
    },
    "firmware": {
        "kw": [
            "firmware",
            "uefi",
            "bios",
            "tpm",
            "smc",
            "mca",
            "microcode",
            "option rom",
            "bootkit",
        ],
        "color": MAGENTA,
    },
    "sidechannel": {
        "kw": [
            "side channel",
            "spectre",
            "meltdown",
            "hardware bug",
            "cpu bug",
            "timing attack",
            "rowhammer",
        ],
        "color": RED,
    },
    "exploit": {
        "kw": [
            "exploit",
            "poc",
            "proof of concept",
            "weaponized",
            "metasploit",
            "c2",
            "shellcode",
        ],
        "color": RED,
    },
    "cve": {"kw": ["cve-", "cve :", "cve ", "cve,"], "color": YELLOW},
    "ransomware": {
        "kw": [
            "ransomware",
            "ransom",
            "extortion",
            "lockbit",
            "blackcat",
            "alphv",
            "clop",
            "akira",
        ],
        "color": RED,
    },
    "supplychain": {
        "kw": [
            "supply chain",
            "dependency",
            "typosquat",
            "backdoor",
            "solarwinds",
            "npm",
            "pypi",
            "package",
            "hijack",
        ],
        "color": YELLOW,
    },
    "ai": {
        "kw": [
            "ai",
            "llm",
            "large language model",
            "machine learning",
            "deepfake",
            "agent",
            "prompt injection",
        ],
        "color": CYAN,
    },
    "zeroday": {
        "kw": [
            "zero-day",
            "zero day",
            "0-day",
            "0day",
            "actively exploited",
            "in the wild",
            "itw",
        ],
        "color": RED,
    },
    "apt": {
        "kw": [
            "apt ",
            "apt-",
            "nation-state",
            "nation state",
            "china",
            "russia",
            "north korea",
            "iran",
            "lazarus",
            "cozy bear",
            "fancy bear",
            "apt28",
            "apt29",
        ],
        "color": MAGENTA,
    },
    "phishing": {
        "kw": [
            "phishing",
            "spear-phishing",
            "social engineering",
            "credential theft",
            "bec",
            "smishing",
        ],
        "color": YELLOW,
    },
    "breach": {
        "kw": [
            "data breach",
            "data leak",
            "leaked",
            "exposed data",
            "records stolen",
            "records exposed",
        ],
        "color": RED,
    },
    "malware": {
        "kw": [
            "malware",
            "trojan",
            "infostealer",
            "wiper",
            "botnet",
            "rat ",
            "loader",
            "stealer",
            "dropper",
        ],
        "color": GREEN,
    },
    "vuln": {
        "kw": [
            "vulnerability",
            "rce",
            "remote code execution",
            "privilege escalation",
            "sqli",
            "xss",
            "patch",
            "critical flaw",
        ],
        "color": BLUE,
    },
    "cloud": {
        "kw": [
            "cloud security",
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "k8s",
            "container",
            "docker",
            "serverless",
        ],
        "color": CYAN,
    },
    "iot": {
        "kw": [
            "iot",
            "embedded",
            "microcontroller",
            "esp32",
            "arm",
            "risc-v",
            "riscv",
            "firmware",
        ],
        "color": BLUE,
    },
    "crypto": {
        "kw": [
            "cryptography",
            "encryption",
            "tls",
            "ssl",
            "certificate",
            "cipher",
            "hash",
            "sha",
            "aes",
            "rsa",
        ],
        "color": YELLOW,
    },
    "network": {
        "kw": [
            "network",
            "dns",
            "tcp/ip",
            "bgp",
            "http",
            "tls",
            "vpn",
            "wireguard",
            "proxy",
        ],
        "color": BLUE,
    },
    "windows": {
        "kw": [
            "windows",
            "microsoft",
            "active directory",
            "ntlm",
            "kerberos",
            "powershell",
            "exchange",
        ],
        "color": CYAN,
    },
    "linux": {"kw": ["linux", "glibc", "systemd", "wayland", "xorg"], "color": YELLOW},
    "macos": {
        "kw": ["macos", "apple", "ios", "iphone", "macbook", "tcc", "sip"],
        "color": WHITE,
    },
    "mobile": {"kw": ["android", "ios", "mobile", "arm"], "color": GREEN},
    "blockchain": {
        "kw": [
            "blockchain",
            "crypto",
            "bitcoin",
            "ethereum",
            "smart contract",
            "defi",
            "web3",
        ],
        "color": ORANGE,
    },
    "privacy": {
        "kw": ["privacy", "surveillance", "tracking", "fingerprint", "gdpr", "ccpa"],
        "color": BLUE,
    },
    "hacktivism": {
        "kw": [
            "hacktivism",
            "anonymous",
            "wikileaks",
            "dox",
            "doxxing",
            "protest",
            "op",
        ],
        "color": MAGENTA,
    },
}

CRAZY_TAGS = {
    "exploit",
    "cve",
    "zeroday",
    "vuln",
    "ransomware",
    "malware",
    "apt",
    "breach",
    "supplychain",
}


def is_crazy_exploit(article):
    return bool(set(article.get("tags", [])) & CRAZY_TAGS)


CACHE_DIR = Path.home() / ".cache" / "wiredIn"
CACHE_TTL = timedelta(minutes=15)
DEFAULT_PROFILE_PATH = (
    Path.home() / "vault" / "L_CACHES" / "event_hitlists" / "profile.md"
)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def tag_article(article):
    text = (article["title"] + " " + article.get("summary", "")).lower()
    tags = []
    for tag_name, tag_info in THREAT_TAGS.items():
        if any(kw in text for kw in tag_info["kw"]):
            tags.append(tag_name)
    article["tags"] = tags

    cves = CVE_PATTERN.findall(text)
    article["cves"] = list(set(cve.upper() for cve in cves))
    return article


def get_tag_color(tag_name):
    info = THREAT_TAGS.get(tag_name, {})
    return info.get("color", DIM)


def format_tags(tags):
    if not tags:
        return ""
    return " ".join(f"{get_tag_color(t)}[{t}]{RESET}" for t in tags[:5])


def format_cves(cves):
    if not cves:
        return ""
    return " ".join(f"{YELLOW}{cve}{RESET}" for cve in cves[:5])


def _strip_json_fences(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1] if "\n" in text else text[3:]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    return text.strip()


def _safe_api_call(payload_dict, api_key, timeout=300):
    try:
        payload = json.dumps(payload_dict).encode("utf-8")
        base_url = (
            os.environ.get("WIREDIN_API_BASE")
            or os.environ.get("NVIDIA_API_BASE")
            or "http://localhost:11434/v1"
        )
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = Request(
            f"{base_url.rstrip('/')}/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )
        with urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            result = json.loads(resp.read())
        text = result["choices"][0]["message"]["content"]
        return text.strip(), None
    except URLError as e:
        return None, f"network error: {getattr(e, 'reason', 'unknown')}"
    except json.JSONDecodeError:
        return None, "invalid JSON response"
    except (KeyError, IndexError):
        return None, "unexpected API response format"
    except OSError as e:
        return None, f"connection error: {e}"


def ai_summarize(articles, count=None):
    api_key = os.environ.get("WIREDIN_API_KEY") or os.environ.get("NVIDIA_API_KEY")
    model = os.environ.get("WIREDIN_MODEL", "qwen2.5-coder:7b")

    to_summarize = articles[:count] if count else articles
    print(
        f"  {DIM}  generating AI summaries for {len(to_summarize)} articles...{RESET}"
    )
    print()

    article_list = "\n\n".join(
        f"[{i}] TITLE: {a['title']}\nSOURCE: {a['source']}\n{a.get('summary', '')[:200]}"
        for i, a in enumerate(to_summarize)
    )

    prompt = f"""You are a threat intel analyst. For each article below, write a single sentence (under 120 chars) that captures the key technical takeaway. Be specific. No fluff. No "The". No dashes.

Respond with ONLY a JSON array of strings in the same order. No markdown.

Articles:
{article_list}"""

    text, err = _safe_api_call(
        {
            "model": model,
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        },
        api_key,
    )

    if err:
        print(f"  {DIM}  AI summary failed: {err}{RESET}", file=sys.stderr)
        return articles

    try:
        summaries = json.loads(_strip_json_fences(text))
        for i, s in enumerate(summaries):
            if i < len(to_summarize):
                to_summarize[i]["ai_summary"] = s
    except (json.JSONDecodeError, TypeError):
        pass

    return articles


def fetch_article_text(url, max_chars=6000):
    try:
        req = Request(url, headers={"User-Agent": "wiredIn/1.0 (deep reader)"})
        with urlopen(req, timeout=15, context=SSL_CTX) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:max_chars]
    except Exception:
        return None


def ai_deep_summarize(articles, count=None):
    api_key = os.environ.get("WIREDIN_API_KEY") or os.environ.get("NVIDIA_API_KEY")
    model = os.environ.get("WIREDIN_MODEL", "qwen2.5-coder:7b")

    to_summarize = articles[:count] if count else articles

    article_blocks = []
    for i, a in enumerate(to_summarize):
        text = fetch_article_text(a["link"])
        if text:
            article_blocks.append(f"[{i}] TITLE: {a['title']}\nCONTENT: {text[:2000]}")
        else:
            article_blocks.append(f"[{i}] TITLE: {a['title']}\nCONTENT: (unavailable)")

    if not any("(unavailable)" not in b for b in article_blocks):
        return articles

    article_list = "\n\n".join(article_blocks)

    prompt = f"""You are a threat intel analyst. For each article below, write 2-3 concise sentences summarizing the key technical details. Include specific vulnerability names, CVE IDs, affected products, attack vectors, and impact where mentioned. Be specific and technical.

Respond with ONLY a JSON array of strings in the same order as the articles. No markdown. No numbering.

Articles:
{article_list}"""

    text, err = _safe_api_call(
        {
            "model": model,
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
        },
        api_key,
        timeout=300,
    )

    if err:
        return articles

    try:
        summaries = json.loads(_strip_json_fences(text))
        for i, s in enumerate(summaries):
            if i < len(to_summarize):
                to_summarize[i]["deep_summary"] = s.strip()
    except (json.JSONDecodeError, TypeError):
        pass

    return articles


def ai_intel_brief(articles, count=10):
    if not articles:
        return None
    api_key = os.environ.get("WIREDIN_API_KEY") or os.environ.get("NVIDIA_API_KEY")
    model = os.environ.get("WIREDIN_MODEL", "qwen2.5-coder:7b")

    top = articles[:count]
    article_list = "\n\n".join(
        f"[{i}] TITLE: {a['title']}\nTAGS: {', '.join(a.get('tags', []))}\nCVES: {', '.join(a.get('cves', []))}\n{a.get('summary', '')[:200]}"
        for i, a in enumerate(top)
    )

    prompt = f"""You are a threat intelligence analyst. Analyze these cybersecurity stories and produce a structured briefing covering:
1. TOP THEME: One sentence on the dominant theme today
2. CRITICAL: Most critical item to act on
3. TREND: Notable trend or shift
4. SYSTEMS IMPACT: What impacts systems/kernel/infrastructure directly

Respond ONLY with a JSON object with keys: theme, critical, trend, systems_impact. No markdown.

Articles:
{article_list}"""

    text, err = _safe_api_call(
        {
            "model": model,
            "max_tokens": 800,
            "messages": [{"role": "user", "content": prompt}],
        },
        api_key,
    )

    if err:
        return None
    try:
        return json.loads(_strip_json_fences(text))
    except (json.JSONDecodeError, TypeError):
        return None


def generate_script(articles, top_n=3):
    api_key = os.environ.get("WIREDIN_API_KEY") or os.environ.get("NVIDIA_API_KEY")
    model = os.environ.get("WIREDIN_MODEL", "qwen2.5-coder:7b")
    stories = articles[:top_n]

    story_block = "\n\n".join(
        f"Story {i}: {a['title']}\nSource: {a['source']}\n{a.get('summary', '')[:200]}"
        for i, a in enumerate(stories, 1)
    )

    prompt = f"""Write a 60-second short-form video script covering these cybersecurity stories. Format:

HOOK: attention grabber (1 line)
STORY 1: 2-3 sentences with key technical detail
STORY 2: 2-3 sentences
STORY 3: 2-3 sentences  
CTA: closing line

Rules: conversational, technically accurate, no emojis, no dashes, under 180 words.

Stories:
{story_block}"""

    text, err = _safe_api_call(
        {
            "model": model,
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        },
        api_key,
    )

    if err:
        return _script_local(stories)
    return text


def _script_local(stories):
    lines = [
        "=" * 50,
        "VIDEO SCRIPT",
        "=" * 50,
        "",
        "[HOOK]",
        "What you need to know in security today.",
        "",
    ]
    for i, a in enumerate(stories, 1):
        lines.append(f"[STORY {i}]")
        lines.append(f"Title: {a['title']}")
        oneliner = make_oneliner(a.get("summary", ""), 120)
        if oneliner:
            lines.append(f"Key point: {oneliner}")
        lines.append(f"Link: {a['link']}")
        lines.append("")
    lines.append("[CTA]")
    lines.append("Follow for daily security updates.")
    return "\n".join(lines)


def export_script(script_text, path="wiredIn_script.md"):
    now = datetime.now().strftime("%A, %B %d %Y")
    content = f"# wiredIn video script\n\n*Generated {now}*\n\n---\n\n{script_text}\n"
    with open(path, "w") as f:
        f.write(content)
    return path


def strip_html(text):
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def parse_date(date_str):
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        pass
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def time_ago(dt):
    if not dt:
        return "recently"
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    s = int(diff.total_seconds())
    if s < 0:
        return "just now"
    if s < 60:
        return "now"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    d = s // 86400
    return f"{d}d" if d < 30 else dt.strftime("%b %d")


def fetch_feed(key, feed_info):
    articles = []
    try:
        req = Request(
            feed_info["url"],
            headers={"User-Agent": "wiredIn/1.0 (security aggregator)"},
        )
        with urlopen(req, timeout=10, context=SSL_CTX) as resp:
            data = resp.read()
    except (URLError, OSError) as e:
        print(
            f"  {DIM}  could not reach {feed_info['name']}: {e}{RESET}", file=sys.stderr
        )
        return articles

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        print(f"  {DIM}  could not parse {feed_info['name']}{RESET}", file=sys.stderr)
        return articles

    ns = {"atom": "http://www.w3.org/2005/Atom"}

    for item in root.findall(".//item"):
        title = item.findtext("title", "").strip()
        link = item.findtext("link", "").strip()
        pub = item.findtext("pubDate", "")
        desc = strip_html(item.findtext("description", ""))
        creator = item.findtext("{http://purl.org/dc/elements/1.1/}creator", "")
        if title:
            articles.append(
                {
                    "source_key": key,
                    "source": feed_info["name"],
                    "color": feed_info["color"],
                    "icon": feed_info["icon"],
                    "type": feed_info.get("type", "news"),
                    "title": strip_html(title),
                    "link": link,
                    "date": parse_date(pub),
                    "summary": desc[:500] if desc else "",
                    "author": strip_html(creator) if creator else "",
                }
            )

    for entry in root.findall(".//atom:entry", ns):
        title = entry.findtext("atom:title", "", ns).strip()
        link_el = entry.find("atom:link[@rel='alternate']", ns)
        if link_el is None:
            link_el = entry.find("atom:link", ns)
        link = link_el.get("href", "") if link_el is not None else ""
        pub = entry.findtext("atom:published", "", ns) or entry.findtext(
            "atom:updated", "", ns
        )
        summary_el = entry.findtext("atom:summary", "", ns) or entry.findtext(
            "atom:content", "", ns
        )
        desc = strip_html(summary_el) if summary_el else ""
        if title:
            articles.append(
                {
                    "source_key": key,
                    "source": feed_info["name"],
                    "color": feed_info["color"],
                    "icon": feed_info["icon"],
                    "type": feed_info.get("type", "news"),
                    "title": strip_html(title),
                    "link": link,
                    "date": parse_date(pub),
                    "summary": desc[:500] if desc else "",
                    "author": "",
                }
            )

    rss_ns = "http://purl.org/rss/1.0/"
    dc_ns = "http://purl.org/dc/elements/1.1/"

    for item in root.findall(f".//{{{rss_ns}}}item"):
        title = item.findtext(f"{{{rss_ns}}}title", "").strip()
        link = item.findtext(f"{{{rss_ns}}}link", "").strip()
        pub = item.findtext(f"{{{dc_ns}}}date", "")
        desc = strip_html(item.findtext(f"{{{rss_ns}}}description", ""))
        creator = item.findtext(f"{{{dc_ns}}}creator", "")
        if title:
            articles.append(
                {
                    "source_key": key,
                    "source": feed_info["name"],
                    "color": feed_info["color"],
                    "icon": feed_info["icon"],
                    "type": feed_info.get("type", "news"),
                    "title": strip_html(title),
                    "link": link,
                    "date": parse_date(pub),
                    "summary": desc[:500] if desc else "",
                    "author": strip_html(creator) if creator else "",
                }
            )

    return articles


def get_cache_path():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / "feeds_cache.pkl"


def load_cache():
    cache_path = get_cache_path()
    if cache_path.exists():
        try:
            with open(cache_path, "rb") as f:
                cached = pickle.load(f)
            if (
                datetime.now(timezone.utc)
                - cached.get("ts", datetime.min.replace(tzinfo=timezone.utc))
                < CACHE_TTL
            ):
                return cached.get("articles", [])
        except (pickle.PickleError, EOFError):
            pass
    return None


def save_cache(articles):
    cache_path = get_cache_path()
    try:
        with open(cache_path, "wb") as f:
            pickle.dump({"ts": datetime.now(timezone.utc), "articles": articles}, f)
    except (OSError, pickle.PickleError):
        pass


def print_header(event=None, mode=""):
    now = datetime.now().strftime("%a %b %d %Y  %H:%M")
    width = 66

    print()
    print(f"  {DIM}{'─' * width}{RESET}")

    mode_suffix = f"  {DIM}· {mode}{RESET}" if mode else ""

    if event and event in EVENTS:
        ev = EVENTS[event]
        print(
            f"  {BOLD}{ev['color']}  ⟐  wiredIn{RESET}  {BOLD}{ev['color']}{ev['name']}{RESET}{mode_suffix}"
        )
    else:
        print(
            f"  {BOLD}{TEAL}  ⟐  wiredIn{RESET}  {DIM}security intelligence briefing{RESET}{mode_suffix}"
        )

    print(f"  {DIM}  {now}{RESET}")
    print(f"  {DIM}{'─' * width}{RESET}")
    print()


def make_oneliner(summary, max_len=200):
    if not summary:
        return ""
    for sep in [". ", ".\n", "! ", "? "]:
        if sep in summary:
            summary = summary[: summary.index(sep) + 1]
            break
    summary = summary.strip()
    if len(summary) > max_len:
        summary = summary[: max_len - 1].rsplit(" ", 1)[0] + "…"
    return summary


def get_terminal_width():
    try:
        import shutil

        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def print_article(
    i, article, verbose=False, show_ai=False, show_cve=False, show_meta=False
):
    color = article["color"]
    ago = time_ago(article["date"])
    title = article["title"]
    indent = "       "
    tw = get_terminal_width()
    wrap_width = tw - 8

    idx = f"{DIM}{str(i).rjust(3)}{RESET}"
    source_tag = f"{color}{BOLD}{article['icon']} {article['source']}{RESET}"

    parts = [f"  {idx}  {source_tag}  {DIM}{ago}{RESET}"]
    if show_meta:
        stype = article.get("type", "")
        if stype:
            stype_colors = {
                "advisory": RED,
                "exploit": GREEN,
                "research": MAGENTA,
                "development": CYAN,
                "ops": YELLOW,
                "analysis": BLUE,
            }
            c = stype_colors.get(stype, DIM)
            parts.append(f"  {DIM}[{RESET}{c}{stype}{RESET}{DIM}]{RESET}")
    if show_cve and article.get("cves"):
        parts.append(f"  {YELLOW}{' '.join(article['cves'][:3])}{RESET}")

    print("".join(parts))

    wrapped_title = textwrap.fill(
        title, width=wrap_width, initial_indent=indent, subsequent_indent=indent
    )
    print(f"{BOLD}{WHITE}{wrapped_title}{RESET}")

    if show_ai and article.get("ai_summary"):
        ws = textwrap.fill(
            f"→ {article['ai_summary']}",
            width=wrap_width,
            initial_indent=indent,
            subsequent_indent=indent + "  ",
        )
        print(f"{CYAN}{ws}{RESET}")
    else:
        oneliner = make_oneliner(article.get("summary", ""))
        if oneliner:
            ws = textwrap.fill(
                oneliner,
                width=wrap_width,
                initial_indent=indent,
                subsequent_indent=indent,
            )
            print(f"{DIM}{ws}{RESET}")

    tags_str = format_tags(article.get("tags", []))
    if tags_str:
        print(f"{indent}{tags_str}")

    print(f"{indent}{DIM}{article['link']}{RESET}")

    if verbose and article["summary"]:
        wrapped = textwrap.fill(
            article["summary"],
            width=wrap_width,
            initial_indent=indent,
            subsequent_indent=indent,
        )
        print(f"{DIM}{wrapped}{RESET}")

    print()


def print_deep_article(i, article):
    color = article["color"]
    ago = time_ago(article["date"])
    title = article["title"]
    tw = get_terminal_width()
    wrap_width = tw - 8
    indent = "       "

    print(f"  {DIM}{'─' * (tw - 2)}{RESET}")
    print(
        f"  {DIM}{str(i).rjust(3)}{RESET}  {color}{BOLD}{article['icon']} {article['source']}{RESET}  {DIM}{ago}{RESET}"
    )
    if article.get("author"):
        print(f"  {DIM}  by {article['author']}{RESET}")
    print()

    wrapped = textwrap.fill(
        title, width=wrap_width, initial_indent="  ", subsequent_indent="  "
    )
    print(f"  {BOLD}{WHITE}{wrapped}{RESET}")
    print()

    if article.get("cves"):
        print(f"  {YELLOW}{'  '.join(article['cves'])}{RESET}")
        print()

    if article.get("tags"):
        print(f"  {format_tags(article['tags'])}")
        print()

    if article.get("summary"):
        wrapped = textwrap.fill(
            article["summary"],
            width=wrap_width,
            initial_indent=indent,
            subsequent_indent=indent,
        )
        print(f"  {WHITE}{wrapped}{RESET}")
        print()

    if article.get("ai_summary"):
        print(f"  {CYAN}→ {article['ai_summary']}{RESET}")
        print()

    if article["link"]:
        print(f"  {DIM}{article['link']}{RESET}")
    print()


def print_intel_line(i, article):
    color = article["color"]
    ago = time_ago(article["date"])
    title = article["title"]
    cves = article.get("cves", [])
    tags = article.get("tags", [])
    tw = get_terminal_width()

    line = f"  {DIM}{str(i).rjust(3)}{RESET}  {color}{article['icon']}{RESET}  {DIM}{ago.rjust(4)}{RESET}  "

    title_avail = tw - len(line) - 4
    if cves:
        cve_str = f"  {YELLOW}{' '.join(cves[:2])}{RESET}"
        title_avail -= len(cve_str) + len(cves[:2]) * 4  # rough
    if tags:
        tag_str = f"  {format_tags(tags[:2])}"
        title_avail -= 8

    title_display = title[:title_avail] + "…" if len(title) > title_avail else title
    line += f"{BOLD}{WHITE}{title_display}{RESET}"

    if tags:
        line += f"  {format_tags(tags[:2])}"
    if cves:
        line += f"  {YELLOW}{' '.join(cves[:2])}{RESET}"

    print(line)


def export_markdown(articles, path="wiredIn_briefing.md"):
    now = datetime.now().strftime("%A, %B %d %Y  %H:%M")
    lines = [f"# wiredIn briefing", f"", f"*Generated {now}*", f"", f"---", f""]
    for i, a in enumerate(articles, 1):
        tags = ", ".join(a.get("tags", []))
        cves = ", ".join(a.get("cves", []))
        lines.append(f"### {i}. {a['title']}")
        lines.append(f"")
        lines.append(f"**Source:** {a['source']}  ")
        lines.append(f"**When:** {time_ago(a['date'])}  ")
        if tags:
            lines.append(f"**Tags:** {tags}  ")
        if cves:
            lines.append(f"**CVEs:** {cves}  ")
        lines.append(f"**Link:** {a['link']}")
        if a.get("ai_summary"):
            lines.append(f"")
            lines.append(f"**AI Summary:** {a['ai_summary']}")
        if a["summary"]:
            lines.append(f"")
            lines.append(f"> {a['summary']}")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return path


def export_html(articles, path="wiredIn_briefing.html"):
    now = datetime.now().strftime("%A, %B %d %Y  %H:%M")
    items_html = ""
    for i, a in enumerate(articles, 1):
        tags = ", ".join(a.get("tags", []))
        cves = ", ".join(a.get("cves", []))
        ai = f"<p><em>AI: {a['ai_summary']}</em></p>" if a.get("ai_summary") else ""
        summary = f"<p>{a['summary'][:300]}</p>" if a["summary"] else ""
        items_html += f"""
        <article>
            <h3><a href="{a["link"]}">{a["title"]}</a></h3>
            <p><strong>{a["source"]}</strong> &middot; {time_ago(a["date"])}</p>
            {summary}
            {ai}
            <p class="meta">{tags}{" | " + cves if cves else ""}</p>
        </article>
        """
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>wiredIn briefing</title>
<style>
body {{ font-family: -apple-system, monospace; max-width: 800px; margin: 2em auto; padding: 0 1em; background: #0d1117; color: #c9d1d9; }}
article {{ border-bottom: 1px solid #30363d; padding: 1em 0; }}
a {{ color: #58a6ff; }}
.meta {{ color: #8b949e; font-size: 0.9em; }}
h1 {{ color: #39d2c0; }}
</style></head><body>
<h1>wiredIn briefing</h1>
<p><em>Generated {now}</em></p>
{items_html}
</body></html>"""
    with open(path, "w") as f:
        f.write(html)
    return path


def load_profile(profile_path=None):
    path = (
        profile_path or os.environ.get("WIREDIN_PROFILE") or str(DEFAULT_PROFILE_PATH)
    )
    path = Path(path)
    if not path.exists():
        return []
    keywords = []
    in_section = False
    try:
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if (
                stripped.lower().startswith("## ")
                and "skill" not in stripped.lower()
                and "interest" not in stripped.lower()
            ):
                in_section = False
            if stripped.lower().startswith("## skills") or stripped.lower().startswith(
                "## interests"
            ):
                in_section = True
                continue
            if in_section and stripped.startswith("- "):
                kw = stripped[2:].strip()
                if kw:
                    keywords.append(kw.lower())
                    keywords.extend(kw.lower().split())
    except (OSError, UnicodeDecodeError):
        return []
    return list(set(keywords))


def main():
    parser = argparse.ArgumentParser(
        description="wiredIn: terminal security intelligence aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              wiredIn                          daily briefing
              wiredIn --event defcon           DEF CON mode
              wiredIn --tag kernel             kernel security filter
              wiredIn --tag linux --cve        CVEs in Linux security
              wiredIn --ai                     AI summaries
              wiredIn --intel                  threat intel briefing
              wiredIn --intel --ai             AI-powered intel brief
              wiredIn --deep                   detailed article view
              wiredIn --cve                    CVE-only mode
              wiredIn --source talos,unit42    research sources only
              wiredIn --export                 markdown export
              wiredIn --export html            HTML export
        """),
    )

    parser.add_argument(
        "--limit", "-n", type=int, default=20, help="headlines to show (default: 20)"
    )
    parser.add_argument(
        "--source",
        "-s",
        type=str,
        default=None,
        help="filter by source key (comma separated)",
    )
    parser.add_argument(
        "--search", "-q", type=str, default=None, help="search headlines"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="show full summaries"
    )
    parser.add_argument(
        "--list", "-l", action="store_true", help="list sources, events, tags"
    )
    parser.add_argument(
        "--export",
        "-e",
        type=str,
        nargs="?",
        const="markdown",
        choices=["markdown", "html", "json"],
        help="export format",
    )
    parser.add_argument("--json", action="store_true", help="output as JSON")
    parser.add_argument(
        "--cve", action="store_true", help="show only articles with CVEs"
    )
    parser.add_argument(
        "--event",
        type=str,
        default=None,
        help="event mode (rsac, defcon, blackhat, bsides)",
    )
    parser.add_argument("--tag", "-t", type=str, default=None, help="filter by tag")
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        nargs="?",
        const=str(DEFAULT_PROFILE_PATH),
        default=None,
        help="filter by profile keywords from resume (default: ~/vault/L_CACHES/event_hitlists/profile.md)",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="AI summaries (needs Ollama or WIREDIN_API_KEY)",
    )
    parser.add_argument(
        "--ai-model",
        type=str,
        default=None,
        help="AI model name (default: qwen2.5-coder:7b, env: WIREDIN_MODEL)",
    )
    parser.add_argument(
        "--intel", action="store_true", help="structured intel briefing"
    )
    parser.add_argument("--deep", action="store_true", help="detailed article view")
    parser.add_argument("--script", action="store_true", help="generate video script")
    parser.add_argument(
        "--script-count", type=int, default=3, help="stories in script (default: 3)"
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="skip cache, force fetch"
    )
    parser.add_argument(
        "--meta", action="store_true", help="show article metadata (type)"
    )
    parser.add_argument(
        "--source-type",
        type=str,
        default=None,
        help="filter by source type (news, analysis, research, advisory, exploit, cve, ops, development)",
    )
    parser.add_argument("--tui", action="store_true", help="launch interactive TUI")

    args = parser.parse_args()

    if args.tui:
        try:
            from wiredIn_tui import main as tui_main
        except ImportError:
            print(
                "TUI requires textual. Install it:\n  pip install textual",
                file=sys.stderr,
            )
            sys.exit(1)
        tui_main()
        return

    if args.ai_model:
        os.environ["WIREDIN_MODEL"] = args.ai_model

    if args.list:
        print(f"\n  {BOLD}{TEAL}feeds:{RESET}\n")
        for key, info in FEEDS.items():
            stype = info.get("type", "")
            print(
                f"    {info['color']}{BOLD}{info['icon']} {key:12}{RESET}  {info['name']:30}  {DIM}{stype}{RESET}"
            )

        print(f"\n  {BOLD}{TEAL}events:{RESET}\n")
        for key, info in EVENTS.items():
            print(f"    {info['color']}{BOLD}  {key:12}{RESET}  {info['name']}")

        print(f"\n  {BOLD}{TEAL}tags:{RESET}\n")
        for key, info in THREAT_TAGS.items():
            print(f"    {info['color']}[{key}]{RESET}")

        print(f"\n  {DIM}wiredIn --tag kernel --cve --ai{RESET}")
        print(f"  {DIM}wiredIn --event defcon --intel{RESET}\n")
        return

    feeds_to_fetch = dict(FEEDS)

    if args.source:
        keys = [k.strip() for k in args.source.split(",")]
        feeds_to_fetch = {k: FEEDS[k] for k in keys if k in FEEDS}
        if not feeds_to_fetch:
            print(f"  {RED}unknown source: {args.source}{RESET}")
            print(f"  {DIM}run wiredIn --list{RESET}")
            return

    if args.source_type:
        feeds_to_fetch = {
            k: v for k, v in feeds_to_fetch.items() if v.get("type") == args.source_type
        }
        if not feeds_to_fetch:
            print(f"  {RED}no sources of type: {args.source_type}{RESET}")
            return

    event_config = None
    if args.event:
        ek = args.event.lower()
        if ek in EVENTS:
            event_config = EVENTS[ek]
        else:
            print(f"  {RED}unknown event: {args.event}{RESET}")
            print(f"  {DIM}events: {', '.join(EVENTS.keys())}{RESET}")
            return

    mode_parts = []
    if args.event:
        mode_parts.append(EVENTS[args.event.lower()]["name"])
    if args.tag:
        mode_parts.append(f"tag:{args.tag}")
    if args.profile:
        mode_parts.append("PROFILE")
    if args.cve:
        mode_parts.append("CVE")
    if args.intel:
        mode_parts.append("INTEL")
    if args.deep:
        mode_parts.append("DEEP")
    if args.ai:
        mode_parts.append("AI")
    mode_str = " | ".join(mode_parts)

    if not args.json:
        print_header(event=args.event, mode=mode_str)

    cached = None if args.no_cache else load_cache()
    if cached is not None:
        all_articles = cached
        if not args.json:
            print(f"  {DIM}  loaded {len(all_articles)} articles from cache{RESET}")
            print()
    else:
        if not args.json:
            print(f"  {DIM}  fetching from {len(feeds_to_fetch)} sources...{RESET}")
            print()

        all_articles = []
        for key, info in feeds_to_fetch.items():
            articles = fetch_feed(key, info)
            all_articles.extend(articles)

        all_articles.sort(
            key=lambda a: a["date"] or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        for a in all_articles:
            tag_article(a)

        save_cache(all_articles)
        if not args.json:
            print(f"  {DIM}  fetched {len(all_articles)} articles{RESET}")
            print()

    if event_config:
        e_kw = event_config["keywords"]
        filtered = [
            a
            for a in all_articles
            if any(
                kw in (a["title"] + " " + a.get("summary", "")).lower() for kw in e_kw
            )
        ]
        if filtered:
            all_articles = filtered
        elif not args.json:
            print(
                f"  {YELLOW}  no {event_config['name']}-specific articles, showing all{RESET}"
            )
            print()

    if args.tag:
        tq = args.tag.lower()
        all_articles = [a for a in all_articles if tq in a.get("tags", [])]

    if args.profile:
        profile_path = (
            None if args.profile == str(DEFAULT_PROFILE_PATH) else args.profile
        )
        p_keywords = load_profile(profile_path)
        if not p_keywords:
            if not args.json:
                print(
                    f"  {YELLOW}  profile not found or empty at {profile_path or DEFAULT_PROFILE_PATH}{RESET}"
                )
                print()
        else:
            all_articles = [
                a
                for a in all_articles
                if any(
                    kw in (a["title"] + " " + a.get("summary", "")).lower()
                    for kw in p_keywords
                )
            ]

    if args.cve:
        all_articles = [a for a in all_articles if a.get("cves")]

    if args.search:
        q = args.search.lower()
        all_articles = [
            a
            for a in all_articles
            if q in a["title"].lower() or q in a.get("summary", "").lower()
        ]

    if not all_articles:
        print(f"  {YELLOW}no articles found.{RESET}")
        return

    display = all_articles[: args.limit]

    show_ai = False
    if args.ai or args.script:
        ai_count = len(display) if args.ai else args.script_count
        all_articles = ai_summarize(all_articles, count=ai_count)
        display = all_articles[: args.limit]
        show_ai = args.ai

    if args.intel:
        intel = ai_intel_brief(all_articles[:10]) if args.ai else None

        print(f"  {BOLD}{TEAL}  ⚡  intel summary{RESET}")
        print(f"  {DIM}  {'─' * 62}{RESET}")
        print()

        if intel:
            for label, key in [
                ("Theme", "theme"),
                ("Critical", "critical"),
                ("Trend", "trend"),
                ("Systems Impact", "systems_impact"),
            ]:
                val = intel.get(key, "")
                if val:
                    print(f"  {BOLD}{label}:{RESET}  {WHITE}{val}{RESET}")
                    print()
        else:
            print(f"  {DIM}  AI intel brief unavailable (is Ollama running?){RESET}")
            print()

        print(f"  {BOLD}{TEAL}  headlines{RESET}")
        print(f"  {DIM}  {'─' * 62}{RESET}")
        print()

        for i, article in enumerate(display, 1):
            print_intel_line(i, article)
        print()
        print(f"  {DIM}{'─' * 62}{RESET}")
        total = len(all_articles)
        print(f"  {DIM}  {len(display)} of {total} articles{RESET}")
        print()
        return

    if args.script:
        script_stories = all_articles[: args.script_count]
        script_text = generate_script(script_stories, top_n=args.script_count)

        print()
        print(f"  {DIM}{'─' * 62}{RESET}")
        print(
            f"  {BOLD}{MAGENTA}  🎬  video script{RESET}  {DIM}short form content{RESET}"
        )
        print(f"  {DIM}{'─' * 62}{RESET}")
        print()

        for line in script_text.split("\n"):
            s = line.strip().upper()
            if (
                s.startswith("[")
                or s.startswith("HOOK")
                or s.startswith("STORY")
                or s.startswith("CTA")
            ):
                print(f"    {BOLD}{CYAN}{line}{RESET}")
            elif s.startswith("="):
                print(f"    {DIM}{line}{RESET}")
            else:
                print(f"    {WHITE}{line}{RESET}")

        print()
        print(f"  {DIM}{'─' * 62}{RESET}")
        print()

        if args.export:
            path = export_script(script_text)
            print(f"  {GREEN}  script exported to {path}{RESET}")
            print()
        return

    if args.json:
        out = []
        for a in display:
            out.append(
                {
                    "source": a["source"],
                    "title": a["title"],
                    "link": a["link"],
                    "date": a["date"].isoformat() if a["date"] else None,
                    "summary": a["summary"],
                    "tags": a.get("tags", []),
                    "cves": a.get("cves", []),
                    "type": a.get("type", ""),
                    "ai_summary": a.get("ai_summary", None),
                }
            )
        print(json.dumps(out, indent=2))
        return

    if args.deep:
        for i, article in enumerate(display, 1):
            print_deep_article(i, article)
        print(f"  {DIM}{'─' * 62}{RESET}")
        print(f"  {DIM}  {len(display)} articles{RESET}")
        print()
    else:
        for i, article in enumerate(display, 1):
            print_article(
                i,
                article,
                verbose=args.verbose,
                show_ai=show_ai,
                show_cve=args.cve,
                show_meta=args.meta,
            )

        print(f"  {DIM}{'─' * 62}{RESET}")
        total = len(all_articles)
        showing = len(display)
        print(
            f"  {DIM}  showing {showing} of {total} articles from {len(feeds_to_fetch)} sources{RESET}"
        )

        if args.cve:
            cve_count = sum(1 for a in all_articles if a.get("cves"))
            print(f"  {DIM}  {cve_count} articles contain CVEs{RESET}")

        if args.tag:
            print(f"  {DIM}  filtered by tag: {args.tag}{RESET}")

        if showing < total:
            print(f"  {DIM}  wiredIn --limit {total} to see all{RESET}")

        tag_counts = Counter(t for a in all_articles for t in a.get("tags", []))
        if tag_counts:
            top_tags = tag_counts.most_common(5)
            tag_summary = "  ".join(
                f"{get_tag_color(t)}[{t}({c})]{RESET}" for t, c in top_tags
            )
            print(f"  {DIM}  top tags: {tag_summary}{RESET}")

        print()

    if args.export:
        fmt = args.export if args.export != "json" else "json"
        if fmt == "markdown":
            path = export_markdown(display)
        elif fmt == "html":
            path = export_html(display)
        else:
            path = "wiredIn_briefing.json"
            with open(path, "w") as f:
                json.dump(
                    [
                        {
                            "source": a["source"],
                            "title": a["title"],
                            "link": a["link"],
                            "tags": a.get("tags", []),
                            "cves": a.get("cves", []),
                        }
                        for a in display
                    ],
                    f,
                    indent=2,
                )
        print(f"  {GREEN}  exported to {path}{RESET}")
        print()


if __name__ == "__main__":
    main()

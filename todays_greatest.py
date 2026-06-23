#!/usr/bin/env python3
"""
today's greatest - ranks vulns by relevance + coolness + popularity
outputs: "today's greatest" (LinkedIn), GREATEST_README.md, video_script.md
"""

import sys
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wiredIn import (
    fetch_feed,
    tag_article,
    FEEDS,
    CVE_PATTERN,
    time_ago,
    load_cache,
    save_cache,
)

TAG_COOLNESS = {
    "zeroday": 10,
    "exploit": 9,
    "ransomware": 8,
    "cve": 7,
    "vuln": 6,
    "breach": 6,
    "apt": 5,
    "supplychain": 5,
    "malware": 4,
    "kernel": 4,
    "firmware": 4,
    "sidechannel": 4,
    "edr": 3,
    "windows": 3,
    "linux": 3,
    "macos": 3,
    "cloud": 2,
    "ai": 2,
    "network": 2,
    "phishing": 2,
    "iot": 2,
}

SOURCE_WEIGHTS = {
    "research": 1.3,
    "analysis": 1.2,
    "ops": 1.1,
    "news": 1.0,
    "advisory": 0.8,
    "exploit": 1.1,
    "development": 0.7,
}

BUZZWORDS = [
    "critical",
    "actively exploited",
    "zero-day",
    "wormable",
    "patch now",
    "rce",
    "remote code execution",
    "privilege escalation",
]


def score_article(article, cve_source_count):
    score = 0
    for t in article.get("tags", []):
        score += TAG_COOLNESS.get(t, 1)
    for cve in article.get("cves", []):
        score += cve_source_count.get(cve, 0) * 3
    score *= SOURCE_WEIGHTS.get(article.get("type", "news"), 1.0)
    date = article.get("date")
    if date:
        now = datetime.now(timezone.utc)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        hours_ago = (now - date).total_seconds() / 3600
        recency = (
            1.5
            if hours_ago < 6
            else 1.3
            if hours_ago < 24
            else 1.1
            if hours_ago < 48
            else 0.9
            if hours_ago < 72
            else 0.5
        )
        score *= recency
    title_lower = (article.get("title") or "").lower()
    for bw in BUZZWORDS:
        if bw in title_lower:
            score += 3
    return round(score, 1)


def fetch_articles():
    cached = load_cache()
    if cached:
        return cached
    all_articles = []
    for key, info in FEEDS.items():
        articles = fetch_feed(key, info)
        all_articles.extend(articles)
    all_articles.sort(
        key=lambda a: a["date"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    for a in all_articles:
        tag_article(a)
    save_cache(all_articles)
    return all_articles


def get_recent(all_articles):
    now = datetime.now(timezone.utc)
    recent = [
        a
        for a in all_articles
        if a.get("date")
        and abs(
            (
                now
                - (
                    a["date"].replace(tzinfo=timezone.utc)
                    if a["date"].tzinfo is None
                    else a["date"]
                )
            ).total_seconds()
            / 3600
        )
        < 96
    ]
    return recent or all_articles


def rank_articles(recent, cve_source_count):
    scored = []
    for a in recent:
        s = score_article(a, cve_source_count)
        scored.append((s, a))
    scored.sort(key=lambda x: -x[0])
    return scored


def generate_linkedin_post(top_cves, top, now, cve_source_map):
    out = []
    out.append("=" * 72)
    out.append("  TODAY'S GREATEST \u2014 Cybersecurity Hits")
    out.append(f"  {now.strftime('%A, %B %d %Y  %H:%M UTC')}")
    out.append("=" * 72)
    out.append("")
    out.append("\u2500\u2500 TOP VULNERABILITIES (with CVEs) \u2500\u2500")
    out.append("")
    for rank, (score, a) in enumerate(top_cves, 1):
        cves = ", ".join(a.get("cves", []))
        ago = time_ago(a["date"])
        out.append(f"  {rank}. {a['title']}")
        out.append(f"     Source: {a['source']}  |  {ago}")
        out.append(f"     CVEs:   {cves}")
        out.append(f"     Tags:   {', '.join(a.get('tags', []))}")
        out.append(f"     Score:  {score}")
        out.append(f"     Link:   {a['link']}")
        out.append("")
    out.append("\u2500\u2500 TRENDING TOPICS \u2500\u2500")
    out.append("")
    for rank, (score, a) in enumerate(top, 1):
        tags = ", ".join(a.get("tags", []))
        cves = ", ".join(a.get("cves", []))
        ago = time_ago(a["date"])
        out.append(f"  {rank}. [{a['source']}] {a['title']}")
        out.append(f"     {ago}  |  Tags: {tags}")
        if cves:
            out.append(f"     CVEs: {cves}")
        out.append(f"     Link: {a['link']}")
        out.append("")
    out.append("\u2500\u2500 CROSS-SOURCE HEAT MAP \u2500\u2500")
    out.append("")
    multi_source = {cve: srcs for cve, srcs in cve_source_map.items() if len(srcs) > 1}
    if multi_source:
        for cve, srcs in sorted(multi_source.items(), key=lambda x: -len(x[1])):
            out.append(
                f"  {cve} \u2014 covered by {len(srcs)} sources: {', '.join(srcs)}"
            )
            out.append("")
    else:
        out.append("  (No CVE covered by multiple sources today)")
        out.append("")
    out.append("=" * 72)
    out.append("  Generated by wiredIn \u00b7 today's greatest")
    out.append("=" * 72)
    return "\n".join(out)


def generate_readme(top_cves, top, now, cve_source_map, all_articles):
    lines = []
    lines.append("# Today's Greatest \u2014 Cybersecurity Hits")
    lines.append("")
    lines.append(f"> Auto-generated on {now.strftime('%A, %B %d %Y at %H:%M UTC')}")
    lines.append(
        f"> From {len(all_articles)} articles across {len(FEEDS)} security feeds"
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## \U0001f525 Top Vulnerabilities (with CVEs)")
    lines.append("")
    lines.append("| # | Vulnerability | Source | CVEs | Score |")
    lines.append("|---|-------------|--------|------|-------|")
    for rank, (score, a) in enumerate(top_cves, 1):
        title = a["title"][:60] + "..." if len(a["title"]) > 60 else a["title"]
        cves = ", ".join(a.get("cves", []))
        safe_cves = cves.replace("|", "/")
        lines.append(f"| {rank} | {title} | {a['source']} | `{safe_cves}` | {score} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## \U0001f4f0 Trending Stories")
    lines.append("")
    for rank, (score, a) in enumerate(top, 1):
        ago = time_ago(a["date"])
        tags = ", ".join(a.get("tags", []))
        cves = ", ".join(a.get("cves", []))
        lines.append(f"### {rank}. {a['title']}")
        lines.append(f"")
        lines.append(f"| | |")
        lines.append(f"|---|---|")
        lines.append(f"| **Source** | {a['source']} |")
        lines.append(f"| **When** | {ago} |")
        lines.append(f"| **Tags** | {tags} |")
        if cves:
            lines.append(f"| **CVEs** | `{cves}` |")
        lines.append(f"| **Score** | {score} |")
        lines.append(f"| **Link** | [{a['link']}]({a['link']}) |")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## \U0001f50d Cross-Source Heat Map")
    lines.append("")
    multi_source = {cve: srcs for cve, srcs in cve_source_map.items() if len(srcs) > 1}
    if multi_source:
        for cve, srcs in sorted(multi_source.items(), key=lambda x: -len(x[1])):
            lines.append(
                f"- **{cve}** \u2014 covered by {len(srcs)} sources: {', '.join(srcs)}"
            )
    else:
        lines.append("_No CVE is covered by multiple sources today._")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        f"*Generated by [wiredIn](https://github.com/anomalyco/wiredIn) \u00b7 {len(all_articles)} articles from {len(FEEDS)} feeds*"
    )
    return "\n".join(lines)


def generate_video_script(top):
    now = datetime.now(timezone.utc)
    lines = []
    lines.append("# Video Script \u2014 Today's Cybersecurity Hits")
    lines.append("")
    lines.append(f"*Generated {now.strftime('%A, %B %d %Y')}*")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Hook
    top_story = top[0][1] if top else None
    if top_story:
        lines.append("[HOOK]")
        hook = f"Today in security: {top_story['title']}"
        lines.append(hook)
        lines.append("")

    # Stories
    for i, (score, a) in enumerate(top[:3], 1):
        lines.append(f"[STORY {i}]")
        lines.append(f"**Headline:** {a['title']}")
        lines.append(f"**Source:** {a['source']} ({time_ago(a['date'])})")
        summary = a.get("summary", "")
        if summary:
            one_liner = (
                summary[: summary.index(". ") + 1] if ". " in summary else summary[:200]
            )
            lines.append(f"**Key detail:** {one_liner}")
        if a.get("cves"):
            lines.append(f"**CVEs:** {', '.join(a['cves'])}")
        if a.get("tags"):
            lines.append(f"**Tags:** {', '.join(a['tags'])}")
        lines.append(f"**Link:** {a['link']}")
        lines.append("")

    # CTA
    lines.append("[CTA]")
    lines.append(
        "Follow for daily cybersecurity updates. Like and share to spread the word."
    )
    lines.append("")

    # Speaker notes
    lines.append("---")
    lines.append(
        "*Speaker notes: Keep each story to 15-20 seconds. Total run time ~60 seconds.*"
    )
    return "\n".join(lines)


def main():
    all_articles = fetch_articles()
    recent = get_recent(all_articles)
    now = datetime.now(timezone.utc)

    cve_source_map = defaultdict(set)
    for a in recent:
        for cve in a.get("cves", []):
            cve_source_map[cve].add(a["source"])
    cve_source_count = {c: len(s) for c, s in cve_source_map.items()}

    scored = rank_articles(recent, cve_source_count)
    top = scored[:15]
    top_cves = [(s, a) for s, a in scored if a.get("cves")][:10]

    base = os.path.dirname(os.path.abspath(__file__))

    # 1. LinkedIn post
    linkedin = generate_linkedin_post(top_cves, top, now, cve_source_map)
    path_linkedin = os.path.join(base, "today's greatest")
    with open(path_linkedin, "w") as f:
        f.write(linkedin)

    # 2. README
    readme = generate_readme(top_cves, top, now, cve_source_map, recent)
    path_readme = os.path.join(base, "GREATEST_README.md")
    with open(path_readme, "w") as f:
        f.write(readme)

    # 3. Video script
    script = generate_video_script(top)
    path_script = os.path.join(base, "video_script.md")
    with open(path_script, "w") as f:
        f.write(script)

    print(linkedin)
    print(f"\n  \u2713 today's greatest    -> {path_linkedin}")
    print(f"  \u2713 GREATEST_README.md  -> {path_readme}")
    print(f"  \u2713 video_script.md     -> {path_script}")


if __name__ == "__main__":
    main()

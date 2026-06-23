#!/usr/bin/env python3
"""wiredIn TUI - interactive terminal security intelligence aggregator"""

import os
import sys
import urllib.request

try:
    from textual.app import App, ComposeResult
    from textual.containers import VerticalScroll
    from textual.screen import Screen
    from textual.widgets import Header, Link, Markdown, Static
    from textual.binding import Binding
    from textual import work
except ImportError:
    print(
        "wiredIn TUI requires textual. Install it:\n  pip install textual",
        file=sys.stderr,
    )
    sys.exit(1)

from datetime import datetime, timezone


def _detect_raw_base() -> str:
    try:
        import subprocess

        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        url = result.stdout.strip()
        if not url:
            return "https://raw.githubusercontent.com/fr4nsyz/wiredIn/main"
        url = url.replace("git@github.com:", "").replace("https://github.com/", "")
        url = url.replace(".git", "").strip("/")
        parts = url.split("/")
        if len(parts) >= 2:
            return f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/main"
    except Exception:
        pass
    return "https://raw.githubusercontent.com/fr4nsyz/wiredIn/main"


GITHUB_RAW_BASE = _detect_raw_base()

from wiredIn import (
    fetch_feed,
    tag_article,
    load_cache,
    save_cache,
    ai_summarize,
    ai_deep_summarize,
    is_crazy_exploit,
    load_profile,
    FEEDS,
    CACHE_DIR,
    time_ago,
)


class GreatestScreen(Screen):
    CSS = """
    Screen {
        background: #0d1117;
    }
    VerticalScroll {
        overflow-y: auto;
        scrollbar-gutter: stable;
    }
    Markdown {
        padding: 0 2;
        margin: 0;
    }
    MarkdownH1 {
        color: #39d2c0;
        text-style: bold;
    }
    MarkdownH2 {
        color: #58a6ff;
        text-style: bold;
    }
    MarkdownH3 {
        color: #e6edf3;
        text-style: bold;
    }
    MarkdownParagraph, MarkdownListItem {
        color: #c9d1d9;
    }
    MarkdownBlockQuote {
        color: #8b949e;
    }
    MarkdownFence {
        color: #d2a8ff;
    }
    MarkdownHorizontalRule {
        color: #30363d;
    }
    MarkdownTable {
        width: 100%;
    }
    #greatest-status {
        height: 1;
        dock: bottom;
        padding: 0 1;
        background: #161b22;
        color: #8b949e;
    }
    """

    BINDINGS = [
        Binding("escape,q", "dismiss", "Back"),
        Binding("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield VerticalScroll(id="greatest-feed")
        yield Static(id="greatest-status")

    def on_mount(self) -> None:
        self._set_status("fetching today's greatest from GitHub...")
        self.fetch_greatest()

    def _set_status(self, text: str) -> None:
        self.query_one("#greatest-status", Static).update(f"  {text}")

    @work(exclusive=True, thread=True)
    def fetch_greatest(self) -> None:
        file_name = "GREATEST_README.md"
        content = None
        try:
            url = f"{GITHUB_RAW_BASE}/{file_name}"
            req = urllib.request.Request(url, headers={"User-Agent": "wiredIn"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8")
        except Exception:
            pass

        if content is None:
            local_path = os.path.join(os.path.dirname(__file__), file_name)
            try:
                with open(local_path) as f:
                    content = f.read()
            except Exception:
                pass

        if content:
            self.app.call_from_thread(self._display_content, content)
        else:
            self.app.call_from_thread(
                self._display_error,
                "file not found on GitHub or locally",
            )

    def _display_content(self, content: str) -> None:
        container = self.query_one("#greatest-feed", VerticalScroll)
        container.remove_children()
        container.mount(Markdown(content))
        self._set_status("today's greatest \u2014 press q to go back")

    def _display_error(self, msg: str) -> None:
        container = self.query_one("#greatest-feed", VerticalScroll)
        container.remove_children()
        container.mount(Static(f"[red]Failed to load today's greatest: {msg}[/red]"))
        self._set_status("failed to load \u2014 press q to go back")

    def action_refresh(self) -> None:
        container = self.query_one("#greatest-feed", VerticalScroll)
        container.remove_children()
        self._set_status("fetching...")
        self.fetch_greatest()


class ArticleWidget(Static):
    def __init__(self, article: dict, index: int, show_deep: bool = False) -> None:
        super().__init__()
        self.article = article
        self.index = index
        self.show_deep = show_deep

    def compose(self) -> ComposeResult:
        a = self.article
        ago = time_ago(a["date"])
        yield Static(f"{a['icon']} {a['source']}  {ago}", classes="source")
        yield Static(f"[bold]{a['title']}[/bold]", classes="title")
        if a.get("ai_summary"):
            yield Static(f"{a['ai_summary']}", classes="summary")
        if a.get("tags"):
            yield Static(" ".join(f"[{t}]" for t in a["tags"][:5]), classes="tags")
        if self.show_deep and a.get("deep_summary"):
            yield Static(a["deep_summary"], classes="deep_summary")
        yield Link(a["link"], url=a["link"], classes="url")


class WiredInTUI(App):
    CSS = """
    Screen {
        background: #0d1117;
    }
    VerticalScroll {
        overflow-y: auto;
        scrollbar-gutter: stable;
    }
    ArticleWidget {
        padding: 0 1;
        margin: 0 0 1 0;
    }
    ArticleWidget:hover {
        background: #161b22;
    }
    ArticleWidget .source {
        color: #8b949e;
    }
    ArticleWidget .title {
        text-style: bold;
        color: #e6edf3;
    }
    ArticleWidget .summary {
        color: #39d2c0;
    }
    ArticleWidget .deep_summary {
        color: #d2a8ff;
    }
    ArticleWidget .tags {
        color: #58a6ff;
    }
    ArticleWidget .url {
        color: #484f58;
    }
    #status {
        height: 1;
        dock: bottom;
        padding: 0 1;
        background: #161b22;
        color: #8b949e;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "toggle_deep_summary", "Read summary"),
        Binding("R", "refresh", "Refresh"),
        Binding("o", "open_link", "Open"),
        Binding("a", "ai_summary", "AI summary"),
        Binding("j,down", "scroll_down", "Down", show=False),
        Binding("k,up", "scroll_up", "Up", show=False),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),
        Binding("t", "view_greatest", "Today's Greatest"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield VerticalScroll(id="feed")
        yield Static(id="status")

    def on_mount(self) -> None:
        self.articles = []
        self.show_deep_summaries = False
        self._set_status("loading...")
        self.load_feeds()

    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(f"  {text}")

    @work(exclusive=True, thread=True)
    def load_feeds(self) -> None:
        cached = load_cache()
        if cached:
            self.articles = cached
            self._apply_filters(cached)
            return

        self.call_from_thread(self._set_status, "fetching feeds...")
        all_articles = []
        for key, info in FEEDS.items():
            articles = fetch_feed(key, info)
            for a in articles:
                tag_article(a)
            all_articles.extend(articles)
            self.call_from_thread(
                self._set_status,
                f"fetched {info['name']}... ({len(all_articles)} articles)",
            )

        all_articles.sort(
            key=lambda a: a["date"] or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        save_cache(all_articles)
        self.articles = all_articles
        self._apply_filters(all_articles)

    def _apply_filters(self, articles: list) -> None:
        p_keywords = load_profile()
        if p_keywords:
            articles = [
                a
                for a in articles
                if any(
                    kw in (a["title"] + " " + a.get("summary", "")).lower()
                    for kw in p_keywords
                )
            ]

        articles = [a for a in articles if is_crazy_exploit(a)]

        articles.sort(
            key=lambda a: a["date"] or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        self.articles = articles
        self.call_from_thread(self._show_articles, articles)

    def _show_articles(self, articles: list) -> None:
        feed = self.query_one("#feed", VerticalScroll)
        feed.remove_children()
        for i, a in enumerate(articles):
            feed.mount(ArticleWidget(a, i, show_deep=self.show_deep_summaries))
        self._set_status(f"showing {len(articles)} articles (profile + crazy exploits)")

    def action_refresh(self) -> None:
        cache_path = CACHE_DIR / "feeds_cache.pkl"
        if cache_path.exists():
            cache_path.unlink()
        feed = self.query_one("#feed", VerticalScroll)
        feed.remove_children()
        self.show_deep_summaries = False
        self._set_status("refreshing...")
        self.load_feeds()

    def action_toggle_deep_summary(self) -> None:
        if not self.articles:
            return
        self.show_deep_summaries = not self.show_deep_summaries
        if self.show_deep_summaries:
            if any(not a.get("deep_summary") for a in self.articles):
                self._set_status("generating deep summaries...")
                self.generate_deep_summaries()
            else:
                self._show_articles(self.articles)
        else:
            self._show_articles(self.articles)

    @work(exclusive=True, thread=True)
    def generate_deep_summaries(self) -> None:
        count = min(15, len(self.articles))
        ai_deep_summarize(self.articles, count=count)
        self.call_from_thread(self._show_articles, self.articles)

    def action_open_link(self) -> None:
        feed = self.query_one("#feed", VerticalScroll)
        scroll_y = feed.scroll_y
        for child in feed.children:
            if isinstance(child, ArticleWidget) and child.region.y >= scroll_y:
                link = child.article.get("link")
                if link:
                    self.open_url(link)
                return

    def action_view_greatest(self) -> None:
        self.push_screen(GreatestScreen())

    def action_ai_summary(self) -> None:
        if not self.articles:
            self._set_status("no articles to summarize")
            return
        self._set_status("generating AI summaries...")
        self.generate_ai_summaries()

    @work(exclusive=True, thread=True)
    def generate_ai_summaries(self) -> None:
        count = min(15, len(self.articles))
        ai_summarize(self.articles, count=count)
        self.call_from_thread(self._show_articles, self.articles)


def main() -> None:
    app = WiredInTUI()
    app.run()


if __name__ == "__main__":
    main()

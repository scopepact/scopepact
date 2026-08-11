from __future__ import annotations

import json
import re
import unittest
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

PUBLIC = Path(__file__).parent / "public"


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.references: list[str] = []
        self.meta: dict[str, list[str]] = {}
        self.structured_data: list[dict[str, object]] = []
        self._structured_chunks: list[str] | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = dict(attrs)
        if identifier := values.get("id"):
            self.ids.add(identifier)
        if tag == "meta" and (key := values.get("name") or values.get("property")):
            if content := values.get("content"):
                self.meta.setdefault(key, []).append(content)
        if tag == "script" and values.get("type") == "application/ld+json":
            self._structured_chunks = []
        for name in ("href", "src"):
            if reference := values.get(name):
                self.references.append(reference)

    def handle_data(self, data: str) -> None:
        if self._structured_chunks is not None:
            self._structured_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._structured_chunks is not None:
            self.structured_data.append(
                json.loads("".join(self._structured_chunks))
            )
            self._structured_chunks = None


class WebsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parser = SiteParser()
        cls.parser.feed((PUBLIC / "index.html").read_text(encoding="utf-8"))

    def test_local_links_and_assets_exist(self) -> None:
        for reference in self.parser.references:
            parsed = urlsplit(reference)
            if parsed.scheme or parsed.netloc:
                continue
            if not parsed.path:
                if parsed.fragment:
                    self.assertIn(parsed.fragment, self.parser.ids, reference)
                continue
            relative = unquote(parsed.path).lstrip("/")
            target = (PUBLIC / relative).resolve()
            self.assertTrue(target.is_relative_to(PUBLIC.resolve()), reference)
            if not target.exists() and not target.suffix:
                target = target.with_suffix(".html")
            self.assertTrue(target.is_file(), reference)

    def test_manifest_and_cloudflare_files_are_valid(self) -> None:
        manifest = json.loads(
            (PUBLIC / "site.webmanifest").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["name"], "ScopePact")
        self.assertTrue((PUBLIC / "_headers").is_file())
        self.assertTrue((PUBLIC / "robots.txt").is_file())
        self.assertTrue((PUBLIC / "sitemap.xml").is_file())
        self.assertTrue((PUBLIC / "feed.xml").is_file())
        self.assertTrue((PUBLIC / "llms.txt").is_file())

    def test_community_entry_points_are_public(self) -> None:
        self.assertIn("community", self.parser.ids)
        self.assertIn(
            "https://github.com/scopepact/scopepact", self.parser.references
        )
        self.assertIn(
            "https://github.com/scopepact/scopepact/discussions",
            self.parser.references,
        )

    def test_public_metadata_uses_custom_domain(self) -> None:
        self.assertIn("https://scopepact.org/", self.parser.references)
        for name in ("index.html", "robots.txt", "sitemap.xml"):
            contents = (PUBLIC / name).read_text(encoding="utf-8")
            self.assertNotIn("scopepact.pages.dev", contents, name)

    def test_discovery_metadata_and_release_boundary_are_explicit(self) -> None:
        contents = (PUBLIC / "index.html").read_text(encoding="utf-8")
        self.assertEqual(len(self.parser.structured_data), 1)
        graph = self.parser.structured_data[0]["@graph"]
        types = {
            entry_type
            for entry in graph
            for entry_type in (
                entry["@type"]
                if isinstance(entry["@type"], list)
                else [entry["@type"]]
            )
        }
        self.assertTrue(
            {"Organization", "WebSite", "WebPage", "SoftwareApplication"}
            <= types
        )
        self.assertEqual(
            self.parser.meta["robots"],
            [
                "index, follow, max-image-preview:large, max-snippet:-1, "
                "max-video-preview:-1"
            ],
        )
        self.assertIn('"codeRepository": "https://github.com/scopepact/scopepact"', contents)
        self.assertIn("MCP authorization proxy", contents)
        self.assertIn("Locally verified, not production approved.", contents)
        self.assertIn("State migration", contents)
        self.assertIn(
            "/articles/ai-agents-need-bounded-authority",
            self.parser.references,
        )

    def test_sitemap_feed_and_machine_readable_brief_are_valid(self) -> None:
        sitemap_root = ET.parse(PUBLIC / "sitemap.xml").getroot()
        sitemap_namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        sitemap_urls = {
            element.text
            for element in sitemap_root.findall("s:url/s:loc", sitemap_namespace)
        }
        article_url = (
            "https://scopepact.org/articles/ai-agents-need-bounded-authority"
        )
        self.assertEqual(
            sitemap_urls,
            {"https://scopepact.org/", article_url},
        )

        feed_root = ET.parse(PUBLIC / "feed.xml").getroot()
        channel = feed_root.find("channel")
        self.assertIsNotNone(channel)
        assert channel is not None
        self.assertEqual(channel.findtext("title"), "ScopePact Field Notes")
        self.assertEqual(channel.findtext("item/link"), article_url)

        brief = (PUBLIC / "llms.txt").read_text(encoding="utf-8")
        self.assertIn("# ScopePact", brief)
        self.assertIn("pre-release research implementation", brief)
        self.assertIn(article_url, brief)
        self.assertIn("https://github.com/scopepact/scopepact", brief)

        robots = (PUBLIC / "robots.txt").read_text(encoding="utf-8")
        self.assertIn("User-agent: *\nAllow: /", robots)
        self.assertIn("Sitemap: https://scopepact.org/sitemap.xml", robots)

    def test_indexnow_verification_key_and_submission_script_match(self) -> None:
        key_files = [
            path
            for path in PUBLIC.glob("*.txt")
            if re.fullmatch(r"[0-9a-f]{32}", path.stem)
        ]
        self.assertEqual(len(key_files), 1)
        key = key_files[0].stem
        self.assertEqual(key_files[0].read_text(encoding="utf-8").strip(), key)
        script = (Path(__file__).parent / "scripts" / "submit-indexnow.mjs").read_text(
            encoding="utf-8"
        )
        self.assertIn(f'const key = "{key}";', script)
        self.assertIn("https://api.indexnow.org/indexnow", script)

    def test_guard_demo_covers_durable_and_failure_states(self) -> None:
        markup = (PUBLIC / "index.html").read_text(encoding="utf-8")
        script = (PUBLIC / "app.js").read_text(encoding="utf-8")
        for case_id in ("allowed", "blocked", "duplicate", "child"):
            self.assertIn(f'data-case="{case_id}"', markup)
        self.assertIn("Synced before forward", script)
        self.assertIn("RECOVERED · DUPLICATE", script)
        self.assertIn("CHILD TERMINATED · FAIL CLOSED", script)

    def test_article_is_medium_ready_and_locally_complete(self) -> None:
        article_path = PUBLIC / "articles" / "ai-agents-need-bounded-authority.html"
        contents = article_path.read_text(encoding="utf-8")
        parser = SiteParser()
        parser.feed(contents)
        self.assertEqual(len(parser.structured_data), 1)
        graph = parser.structured_data[0]["@graph"]
        graph_types = {entry["@type"] for entry in graph}
        self.assertIn("TechArticle", graph_types)
        self.assertIn("BreadcrumbList", graph_types)
        self.assertIn(
            "index, follow, max-image-preview:large, max-snippet:-1, "
            "max-video-preview:-1",
            parser.meta["robots"],
        )
        self.assertIn('property="og:type" content="article"', contents)
        self.assertIn(
            '<link rel="canonical" href="https://scopepact.org/articles/ai-agents-need-bounded-authority"',
            contents,
        )
        self.assertIn("AI Agents Need Bounded Authority, Not More Trust", contents)
        self.assertIn("Current status: pre-release research implementation.", contents)
        self.assertIn(
            "/assets/scopepact-workbench-2026-08-11.png",
            parser.references,
        )
        self.assertIn("/article.css", parser.references)
        for reference in parser.references:
            parsed = urlsplit(reference)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = (PUBLIC / unquote(parsed.path).lstrip("/")).resolve()
            self.assertTrue(target.is_relative_to(PUBLIC.resolve()), reference)
            if target.is_dir():
                target = target / "index.html"
            self.assertTrue(target.is_file(), reference)
        sitemap = (PUBLIC / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn(
            "https://scopepact.org/articles/ai-agents-need-bounded-authority",
            sitemap,
        )


if __name__ == "__main__":
    unittest.main()

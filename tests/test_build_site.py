import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_site

ROOT = Path(__file__).resolve().parents[1]


def render(markdown, source="docs/guide/server.md", page="docs/server.html"):
    return build_site.Renderer(source, build_site.rewriter(source, page)).render(markdown)


class RendererTest(unittest.TestCase):
    def test_renders_the_markdown_the_guide_uses(self):
        title, body = render(
            "# Set up\n\nRun `covee setup <network>` and **confirm**.\n\n"
            "## 1. Prepare a server\n\n"
            "- **A cloud VM**, with:\n  - TCP 443;\n  - UDP 3478.\n- A server at home\n\n"
            "1. First\n2. Second\n\n"
            "```sh\ncovee status home   # check it\n```\n\n"
            "| Computer | Archive |\n| --- | --- |\n| Mac | `covee_<v>.tar.gz` |\n")
        self.assertEqual(title, "Set up")
        self.assertIn("<h1>Set up</h1>", body)
        self.assertIn("<p>Run <code>covee setup &lt;network&gt;</code> and <strong>confirm</strong>.</p>", body)
        self.assertIn('<h2 id="1-prepare-a-server">1. Prepare a server</h2>', body)
        self.assertIn("<li><strong>A cloud VM</strong>, with:\n<ul>\n<li>TCP 443;</li>\n<li>UDP 3478.</li>\n</ul></li>", body)
        self.assertIn("<ol>\n<li>First</li>\n<li>Second</li>\n</ol>", body)
        self.assertIn('<pre><code class="language-sh">covee status home   # check it</code></pre>', body)
        self.assertIn("<th>Computer</th>", body)
        self.assertIn("<td><code>covee_&lt;v&gt;.tar.gz</code></td>", body)

    def test_links_to_guide_pages_become_site_pages_and_others_github(self):
        _, body = render("# Links\n\n[next](devices.md#iphone), [all](README.md), [cli](../cli.md), "
                         "[license](../../LICENSE), [web](https://example.com/?a=1&b=2), [here](#links)\n")
        self.assertIn('<a href="devices.html#iphone">next</a>', body)
        self.assertIn('<a href="index.html">all</a>', body)
        self.assertIn('<a href="https://github.com/covee-io/covee/blob/main/docs/cli.md">cli</a>', body)
        self.assertIn('<a href="https://github.com/covee-io/covee/blob/main/LICENSE">license</a>', body)
        self.assertIn('<a href="https://example.com/?a=1&amp;b=2">web</a>', body)
        self.assertIn('<a href="#links">here</a>', body)

    def test_a_link_from_the_privacy_page_is_relative_to_it(self):
        _, body = render("# Privacy\n\nSee [security](../docs/guide/security.md).\n",
                         source="website/privacy.md", page="privacy.html")
        self.assertIn('<a href="docs/security.html">security</a>', body)

    def test_repeated_headings_get_distinct_anchors(self):
        _, body = render("# Page\n\n## Mac\n\n## Mac\n")
        self.assertIn('id="mac"', body)
        self.assertIn('id="mac-1"', body)

    def test_stops_on_markdown_it_cannot_render(self):
        cases = {
            "# T\n\n```sh\nnever closed\n": "not closed",
            "# T\n\n- item\n  - nested\n  more text\n": "text after a nested list",
            "# T\n\n> a quote\n": "not supported",
            "# T\n\n<div>raw</div>\n": "not supported",
            "# T\n\n- item\n continued badly\n": "indent this line by 2 spaces",
            "# T\n\nan `open code span\n": "code span is not closed",
            "# T\n\n# Second title\n": "one title",
            "No title here\n": "needs a title",
            "# T\n\n[gone](missing.md)\n": "not in the repository",
            "# T\n\n| a | b |\n| --- | --- |\n| 1 |\n": "this row has 1 cells",
        }
        for markdown, message in cases.items():
            with self.subTest(markdown=markdown), self.assertRaisesRegex(build_site.SiteError, message):
                render(markdown)


class GuideSourceTest(unittest.TestCase):
    def test_the_guide_has_no_html_outside_code(self):
        # GitHub drops what looks like an HTML tag, so a placeholder such as
        # <network> must sit in a code span to show on GitHub as on the site.
        for source in build_site.PAGES:
            fenced = False
            for number, line in enumerate((ROOT / source).read_text(encoding="utf-8").split("\n"), 1):
                if line.startswith("```"):
                    fenced = not fenced
                elif not fenced:
                    with self.subTest(source=source, line=number):
                        self.assertIsNone(re.search(r"<[A-Za-z/!]", re.sub(r"`[^`]*`", "", line)), line)


class BuildTest(unittest.TestCase):
    def test_builds_every_page_with_working_links(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "site"
            files = build_site.build(out)
            for name in ("index.html", "docs/index.html", "docs/server.html", "docs/gateway.html",
                         "privacy.html", "404.html", "CNAME", "style.css", "site.js", "favicon.svg"):
                self.assertIn(name, files)
            landing = (out / "index.html").read_text(encoding="utf-8")
            self.assertTrue(landing.startswith("<!doctype html>"))
            self.assertEqual(landing.count("<title>"), 1)
            self.assertNotIn("<!--#header-->", landing)
            server = (out / "docs/server.html").read_text(encoding="utf-8")
            self.assertIn("<title>Set up your network · Covee</title>", server)
            self.assertIn('<a href="server.html" aria-current="page">Set up your network</a>', server)
            self.assertIn('<a class="prev" href="install.html">', server)
            self.assertIn('<a class="next" href="devices.html">', server)
            self.assertNotIn("<p>Next: ", server)
            self.assertEqual((out / "CNAME").read_text(), "covee.io\n")

    def test_the_site_loads_nothing_from_other_sites(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "site"
            build_site.build(out)
            for page in out.rglob("*.html"):
                text = page.read_text(encoding="utf-8")
                with self.subTest(page=page.name):
                    self.assertIsNone(re.search(r'<(script|img|iframe)[^>]+src="(https?:)?//', text))
                    self.assertIsNone(re.search(r'<link[^>]+rel="(stylesheet|preconnect|icon)"[^>]+href="(https?:)?//', text))
                    self.assertIsNone(re.search(r"@import|url\((https?:)?//", (out / "style.css").read_text()))

    def test_a_preview_has_the_landing_page_without_its_document_head(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "preview"
            files = build_site.build(out, preview=True)
            self.assertTrue((out / "index.html").read_text(encoding="utf-8").startswith("<title>Covee</title>"))
            self.assertTrue((out / "docs/index.html").read_text(encoding="utf-8").startswith("<!doctype html>"))
            self.assertNotIn("CNAME", files)
            self.assertNotIn("404.html", files)

    def test_broken_links_stop_the_build(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            (out / "docs").mkdir()
            (out / "index.html").write_text('<a href="docs/missing.html">x</a> <a href="docs/a.html#nowhere">y</a>')
            (out / "docs/a.html").write_text('<h2 id="here">A</h2>')
            with self.assertRaises(build_site.SiteError) as caught:
                build_site.check_links(out)
            self.assertIn("docs/missing.html leads to a missing file", str(caught.exception))
            self.assertIn("docs/a.html#nowhere leads to a missing section", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

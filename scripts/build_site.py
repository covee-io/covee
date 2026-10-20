#!/usr/bin/env python3
"""Build the covee.io website into a folder that GitHub Pages serves as is.

The landing page and its assets come from website/. The guide's pages are
rendered from docs/guide, so the guide has one source for readers on GitHub
and on the site. The renderer covers the Markdown the guide uses and stops on
anything else, and every link and section anchor in the built site is
checked, so a page never ships half-rendered or pointing nowhere.

    python3 scripts/build_site.py                  # into dist/site
    python3 scripts/build_site.py --preview DIR    # the landing page without its
                                                   # document head, for a host
                                                   # that adds its own
"""

from __future__ import annotations

import argparse
import html
import posixpath
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/covee-io/covee"
DOMAIN = "covee.io"
DESCRIPTION = ("Covee builds your own private network on a server you own: direct, encrypted WireGuard "
               "connections between your devices, sign-in with Microsoft, Google or Apple, and a gateway to "
               "private networks. Free and open source.")

# The guide in reading order; each repository path → its published path.
GUIDE = [f"docs/guide/{name}" for name in ("README.md", "introduction.md", "install.md", "server.md",
                                            "devices.md", "gateway.md", "operations.md", "security.md")]
PAGES = {source: "docs/index.html" if source.endswith("README.md") else f"docs/{Path(source).stem}.html"
         for source in GUIDE}
PAGES["website/privacy.md"] = "privacy.html"
# Published path → repository path, copied as they are.
ASSETS = {"style.css": "website/style.css", "site.js": "website/site.js",
          "favicon.svg": "docs/brand/covee-mark.svg", "favicon-64.png": "docs/brand/covee-favicon-64.png"}

NAV = [("Guide", "docs/index.html"), ("Download", "index.html#download"),
       ("Security", "docs/security.html"), ("GitHub", REPO_URL)]
MARK = ('<svg viewBox="0 0 824 824" aria-hidden="true"><defs><linearGradient id="covee-mark" '
        'gradientUnits="userSpaceOnUse" x1="60" y1="24" x2="780" y2="804"><stop offset="0" stop-color="#22C3D6"/>'
        '<stop offset=".55" stop-color="#2563EB"/><stop offset="1" stop-color="#2A3FC9"/></linearGradient></defs>'
        '<rect width="824" height="824" rx="185" fill="url(#covee-mark)"/><path d="M 525.4 230.5 A 214 214 0 1 0 '
        '525.4 593.5" fill="none" stroke="#fff" stroke-width="78" stroke-linecap="round"/><circle cx="595.4" '
        'cy="301.8" r="46" fill="#fff"/><circle cx="595.4" cy="522.2" r="46" fill="#fff"/><circle cx="412" '
        'cy="412" r="54" fill="#fff"/></svg>')

CODE_SPAN = re.compile(r"`([^`\n]+)`")
LINK = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
BOLD = re.compile(r"\*\*(.+?)\*\*")
ITEM = re.compile(r"(\d+\.|[-*]) (.*)")
HEADING = re.compile(r"(#{1,4}) (.+)")
FENCE = re.compile(r"```([\w-]*)\s*$")
RULE_ROW = re.compile(r"\|(\s*:?-{3,}:?\s*\|)+\s*$")
SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:")
NEXT = re.compile(r"\n+Next: [^\n]*\n*\Z")


class SiteError(Exception):
    """The site cannot be built as it is; the message says where and why."""


def plain(text):
    """The words of a Markdown line, without its markup."""
    return LINK.sub(r"\1", text).replace("`", "").replace("**", "")


def slug(text):
    """The anchor GitHub gives a heading, so links work on GitHub and the site alike."""
    return re.sub(r"[^\w\- ]", "", plain(text).strip().lower()).replace(" ", "-")


def summary(markdown):
    """The page's first paragraph, cut to a search-result length."""
    for block in re.split(r"\n\s*\n", markdown):
        block = block.strip()
        if block and not block.startswith(("#", "-", "|", "```")) and not ITEM.match(block):
            text = " ".join(plain(block).split())
            if len(text) <= 160:
                return text
            cut = text[:157].rsplit(" ", 1)[0]
            return cut.rstrip(",;:") + "…"
    return DESCRIPTION


class Renderer:
    """Renders one page of the guide's Markdown: headings, paragraphs, lists
    (nested one inside another), fenced code, tables, code spans, bold text
    and links."""

    def __init__(self, where, rewrite):
        self.where = where
        self.rewrite = rewrite
        self.anchors = []

    def fail(self, line, message):
        raise SiteError(f"{self.where}:{line}: {message}")

    def inline(self, text, line):
        codes = []

        def keep(match):
            codes.append("<code>" + html.escape(match.group(1), quote=False) + "</code>")
            return f"\x00{len(codes) - 1}\x00"

        text = html.escape(CODE_SPAN.sub(keep, text), quote=False)
        if "`" in text:
            self.fail(line, "a code span is not closed")

        def link(match):
            return f'<a href="{html.escape(self.rewrite(html.unescape(match.group(2)), line))}">{match.group(1)}</a>'

        text = BOLD.sub(r"<strong>\1</strong>", LINK.sub(link, text))
        if "**" in text or "](" in text:
            self.fail(line, "bold text or a link is not finished")
        return re.sub("\x00(\\d+)\x00", lambda match: codes[int(match.group(1))], text)

    @staticmethod
    def starts_block(line):
        return bool(FENCE.match(line) or HEADING.match(line) or ITEM.match(line) or line.startswith("|"))

    def render(self, markdown):
        """The page's title and its body as HTML."""
        lines = markdown.split("\n")
        out, title, i = [], None, 0
        while i < len(lines):
            line, number = lines[i], i + 1
            if not line.strip():
                i += 1
            elif FENCE.match(line):
                end = next((j for j in range(i + 1, len(lines)) if lines[j].startswith("```")), None)
                if end is None or lines[end].strip() != "```":
                    self.fail(number, "a code block is not closed with a line of ```")
                language = FENCE.match(line).group(1)
                code = html.escape("\n".join(lines[i + 1:end]), quote=False)
                kind = f' class="language-{language}"' if language else ""
                out.append(f'<div class="code"><pre><code{kind}>{code}</code></pre></div>')
                i = end + 1
            elif HEADING.match(line):
                hashes, text = HEADING.match(line).groups()
                if len(hashes) == 1:
                    if title is not None:
                        self.fail(number, "a page has one title; start sections with ##")
                    title = plain(text)
                    out.append(f"<h1>{self.inline(text, number)}</h1>")
                else:
                    anchor, n = slug(text), 0
                    while (anchor if not n else f"{anchor}-{n}") in self.anchors:
                        n += 1
                    anchor = anchor if not n else f"{anchor}-{n}"
                    self.anchors.append(anchor)
                    out.append(f'<h{len(hashes)} id="{anchor}">{self.inline(text, number)}</h{len(hashes)}>')
                i += 1
            elif line.startswith("|"):
                end = i
                while end < len(lines) and lines[end].startswith("|"):
                    end += 1
                out.append(self.table(lines[i:end], number))
                i = end
            elif ITEM.match(line):
                end = i + 1
                while end < len(lines) and lines[end].strip() and (lines[end].startswith(" ") or ITEM.match(lines[end])):
                    end += 1
                out.append(self.list(lines[i:end], number))
                i = end
            elif line.startswith((" ", "\t", ">", "<", "#")):
                self.fail(number, f"this Markdown is not supported on the site: {line.strip()[:50]}")
            else:
                end = i + 1
                while end < len(lines) and lines[end].strip() and not self.starts_block(lines[end]):
                    end += 1
                out.append("<p>" + self.inline(" ".join(part.strip() for part in lines[i:end]), number) + "</p>")
                i = end
        if title is None:
            raise SiteError(f"{self.where}: the page needs a title, a first line starting with '# '")
        return title, "\n".join(out)

    def list(self, lines, number):
        first = ITEM.match(lines[0])
        ordered = first.group(1)[0].isdigit()
        items = []
        for offset, line in enumerate(lines):
            match = ITEM.match(line)
            if match:
                if match.group(1)[0].isdigit() != ordered:
                    self.fail(number + offset, "a list mixes numbers and bullets")
                items.append((number + offset, len(match.group(1)) + 1, [match.group(2)]))
                continue
            start, width, body = items[-1]
            if len(line) - len(line.lstrip(" ")) < width:
                self.fail(number + offset, f"indent this line by {width} spaces to keep it in the list item above")
            body.append(line[width:])
        rendered = []
        for start, width, body in items:
            text, nested = [], []
            for line in body:
                (nested if nested or ITEM.match(line) else text).append(line)
            item = self.inline(" ".join(part.strip() for part in text), start)
            if nested:
                if any(not ITEM.match(line) and not line.startswith(" ") for line in nested):
                    self.fail(start, "text after a nested list is not supported; move it before the list")
                item += "\n" + self.list(nested, start + len(text))
            rendered.append(f"<li>{item}</li>")
        tag = "ol" if ordered else "ul"
        begin = int(first.group(1)[:-1]) if ordered else 1
        opening = f'<ol start="{begin}">' if begin != 1 else f"<{tag}>"
        return opening + "\n" + "\n".join(rendered) + f"\n</{tag}>"

    def table(self, lines, number):
        if len(lines) < 2 or not RULE_ROW.match(lines[1].strip()):
            self.fail(number, "a table needs a header row, then a row of ---")

        def cells(line, at):
            if not line.rstrip().endswith("|"):
                self.fail(at, "end each table row with |")
            return [cell.strip() for cell in line.strip()[1:-1].split("|")]

        head = cells(lines[0], number)
        rows = [cells(line, number + 2 + k) for k, line in enumerate(lines[2:])]
        for k, row in enumerate(rows):
            if len(row) != len(head):
                self.fail(number + 2 + k, f"this row has {len(row)} cells; the header has {len(head)}")
        out = ['<div class="table-scroll"><table>',
               "<thead><tr>" + "".join(f"<th>{self.inline(cell, number)}</th>" for cell in head) + "</tr></thead>",
               "<tbody>"]
        out += ["<tr>" + "".join(f"<td>{self.inline(cell, number + 2 + k)}</td>" for cell in row) + "</tr>"
                for k, row in enumerate(rows)]
        out.append("</tbody></table></div>")
        return "\n".join(out)


def rewriter(source, page):
    """Turns a link written for the repository into one that works on the site:
    guide pages become site pages, other files their page on GitHub."""
    folder = posixpath.dirname(source)

    def rewrite(url, line):
        if SCHEME.match(url):
            return url
        if url.startswith("#"):
            return url
        path, _, anchor = url.partition("#")
        target = posixpath.normpath(posixpath.join(folder, path))
        suffix = f"#{anchor}" if anchor else ""
        if target in PAGES:
            return posixpath.relpath(PAGES[target], posixpath.dirname(page) or ".") + suffix
        if target.startswith("..") or not (ROOT / target).exists():
            raise SiteError(f"{source}:{line}: the link {url} points to {target}, which is not in the repository")
        kind = "tree" if (ROOT / target).is_dir() else "blob"
        return f"{REPO_URL}/{kind}/main/{target}{suffix}"

    return rewrite


def document_head(title, description, root, canonical, *, title_tag=True):
    head = ["<!doctype html>", '<html lang="en">', '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">']
    if title_tag:
        head.append(f"<title>{html.escape(title)}</title>")
    head += [f'<meta name="description" content="{html.escape(description)}">',
             f'<link rel="canonical" href="https://{DOMAIN}/{canonical}">',
             f'<meta property="og:title" content="{html.escape(title)}">',
             f'<meta property="og:description" content="{html.escape(description)}">',
             f'<meta property="og:url" content="https://{DOMAIN}/{canonical}">',
             '<meta property="og:type" content="website">',
             f'<link rel="icon" href="{root}favicon.svg" type="image/svg+xml">',
             f'<link rel="icon" href="{root}favicon-64.png" type="image/png" sizes="64x64">']
    if title_tag:
        head.append(f'<link rel="stylesheet" href="{root}style.css">')
    return "\n".join(head) + "\n"


def header(root, current=None):
    links = []
    for label, href in NAV:
        url = href if SCHEME.match(href) else root + href
        mark = ' aria-current="page"' if href == current else ""
        links.append(f'<a href="{url}"{mark}>{label}</a>')
    links = "".join(links)
    return (f'<header class="top">\n  <div class="wrap">\n'
            f'    <a class="brand" href="{root}index.html" aria-label="Covee home">{MARK}Covee</a>\n'
            f'    <nav class="nav" aria-label="Site">{links}</nav>\n  </div>\n</header>')


def footer(root):
    return (f'<footer class="site-footer">\n  <div class="wrap">\n    <div class="notes">\n'
            f'      <p>© 2026 Helder Feixas. Covee is free software under the Apache 2.0 license.</p>\n'
            f'      <p>Covee is not affiliated with Tailscale Inc. This site sets no cookies and loads nothing from other sites.</p>\n'
            f'    </div>\n    <nav aria-label="Footer"><a href="{root}docs/index.html">Guide</a>'
            f'<a href="{root}privacy.html">Privacy</a><a href="{root}docs/security.html">Security</a>'
            f'<a href="{REPO_URL}">GitHub</a></nav>\n  </div>\n</footer>')


def page_title(title):
    return title if "Covee" in title else f"{title} · Covee"


def guide_page(source, page, title, body, description, titles):
    root = "../" * page.count("/")
    position = GUIDE.index(source)
    entries = []
    for other in GUIDE:
        label = "Overview" if other.endswith("README.md") else titles[other]
        current = ' aria-current="page"' if other == source else ""
        entries.append(f'<li><a href="{posixpath.basename(PAGES[other])}"{current}>{html.escape(label)}</a></li>')
    pager = []
    if position > 0:
        before = GUIDE[position - 1]
        label = "Overview" if before.endswith("README.md") else titles[before]
        pager.append(f'<a class="prev" href="{posixpath.basename(PAGES[before])}"><span>Previous</span>'
                     f'<strong>{html.escape(label)}</strong></a>')
    if position + 1 < len(GUIDE):
        after = GUIDE[position + 1]
        pager.append(f'<a class="next" href="{posixpath.basename(PAGES[after])}"><span>Next</span>'
                     f'<strong>{html.escape(titles[after])}</strong></a>')
    current = "docs/security.html" if page == "docs/security.html" else "docs/index.html"
    return (document_head(page_title(title), description, root, page) + header(root, current) +
            '\n<main class="wrap docs">\n<nav class="toc" aria-label="Guide">\n<p class="toc-title">Guide</p>\n<ol>\n' +
            "\n".join(entries) + "\n</ol>\n</nav>\n<article class=\"prose\">\n" + body + "\n" +
            f'<nav class="pager" aria-label="Pages">{"".join(pager)}</nav>\n'
            f'<p class="edit"><a href="{REPO_URL}/edit/main/{source}">Suggest a change to this page</a></p>\n'
            "</article>\n</main>\n" + footer(root) + f'\n<script src="{root}site.js"></script>\n')


def plain_page(page, title, body, description):
    root = "../" * page.count("/")
    return (document_head(page_title(title), description, root, page) + header(root) +
            '\n<main class="wrap page">\n<article class="prose">\n' + body + "\n</article>\n</main>\n" +
            footer(root) + f'\n<script src="{root}site.js"></script>\n')


def not_found_page():
    body = ('<h1>This page does not exist</h1>\n<p>The address may be mistyped, or the page has moved. '
            'Start from the <a href="/index.html">home page</a> or the <a href="/docs/index.html">guide</a>.</p>')
    return (document_head("Page not found · Covee", DESCRIPTION, "/", "404.html") + header("/") +
            '\n<main class="wrap page">\n<article class="prose">\n' + body + "\n</article>\n</main>\n" + footer("/") + "\n")


def check_links(out):
    """Every local link and image in the site must lead to a file, and every
    #section to an id on that page."""
    pages = {path.relative_to(out).as_posix(): path.read_text(encoding="utf-8") for path in out.rglob("*.html")}
    ids = {name: set(re.findall(r'\sid="([^"]+)"', text)) for name, text in pages.items()}
    problems = []
    for name, text in sorted(pages.items()):
        for url in re.findall(r'\s(?:href|src)="([^"]*)"', text):
            if SCHEME.match(url) or url.startswith("//"):
                continue
            path, _, anchor = html.unescape(url).partition("#")
            if path.startswith("/"):
                target = path.lstrip("/") or "index.html"
            elif path:
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), path))
            else:
                target = name
            if target.endswith("/") or (out / target).is_dir():
                target = posixpath.join(target, "index.html")
            if not (out / target).is_file():
                problems.append(f"{name}: {url} leads to a missing file")
            elif anchor and target.endswith(".html") and anchor not in ids.get(target, set()):
                problems.append(f"{name}: {url} leads to a missing section")
    if problems:
        raise SiteError("the site has broken links:\n  " + "\n  ".join(problems))


def build(out, *, preview=False):
    """Writes the site into out (replacing it) and returns the published paths."""
    rendered = {}
    for source, page in PAGES.items():
        text = NEXT.sub("\n", (ROOT / source).read_text(encoding="utf-8"))
        title, body = Renderer(source, rewriter(source, page)).render(text)
        rendered[source] = (page, title, body, summary(text.split("\n", 1)[1] if "\n" in text else ""))
    landing = (ROOT / "website/index.html").read_text(encoding="utf-8")
    for marker in ("<!--#header-->", "<!--#footer-->"):
        if landing.count(marker) != 1:
            raise SiteError(f"website/index.html needs {marker} exactly once")
    landing = landing.replace("<!--#header-->", header("")).replace("<!--#footer-->", footer(""))

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    titles = {source: title for source, (_, title, _, _) in rendered.items()}
    for source, (page, title, body, description) in rendered.items():
        (out / page).parent.mkdir(parents=True, exist_ok=True)
        text = (guide_page(source, page, title, body, description, titles) if source in GUIDE
                else plain_page(page, title, body, description))
        (out / page).write_text(text, encoding="utf-8")
    head = "" if preview else document_head("Covee", DESCRIPTION, "", "", title_tag=False)
    (out / "index.html").write_text(head + landing, encoding="utf-8")
    for published, source in ASSETS.items():
        shutil.copyfile(ROOT / source, out / published)
    if not preview:
        (out / "404.html").write_text(not_found_page(), encoding="utf-8")
        (out / "CNAME").write_text(DOMAIN + "\n", encoding="utf-8")
    check_links(out)
    return sorted(path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file())


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the covee.io website.")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "site", help="where to write the site (replaced)")
    parser.add_argument("--preview", type=Path, metavar="DIR",
                        help="write a preview instead: the landing page without its document head")
    args = parser.parse_args(argv)
    out = (args.preview or args.output).resolve()
    if out == ROOT or ROOT.is_relative_to(out):
        parser.error(f"{out} would replace the repository")
    try:
        files = build(out, preview=bool(args.preview))
    except SiteError as error:
        print(f"build_site: {error}", file=sys.stderr)
        return 1
    print(f"Built {len(files)} files into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

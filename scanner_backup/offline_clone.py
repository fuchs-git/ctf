#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nessus_clone_allinone.py (fixed + full)
- crawls all host vulnerabilities from Nessus scan
- saves each host as cleaned static HTML (with screenshot)
- builds index.html
- can rebuild website via --build-website (extracts screenshots from detail pages)
"""

import argparse, asyncio, re, html as html_lib, ipaddress
from pathlib import Path
from urllib.parse import urlparse
from asyncio import Semaphore

try:
    from playwright.async_api import async_playwright
except Exception:
    async_playwright = None


# ---------------- HTML cleanup ----------------
def clean_vuln_table_from_html(src_html: str, host_title: str, screenshot_name=None) -> str:
    rows = re.findall(r'(?is)<tr[^>]*class=["\'][^"\']*vulnerability[^"\']*["\'][^>]*>(.*?)</tr>', src_html)
    parsed = []
    for row_html in rows:
        tds = re.findall(r'(?is)<td[^>]*>(.*?)</td>', row_html)
        cells = [re.sub(r'(?is)<.*?>', '', td).strip() for td in tds]
        if cells:
            while len(cells) < 7:
                cells.append("")
            parsed.append(cells[:7])

    if not parsed:
        vuln_html = "<p><em>No vulnerabilities found for this host.</em></p>"
    else:
        rows_html = "\n".join(
            "<tr>" + "".join(f"<td>{html_lib.escape(c)}</td>" for c in row) + "</tr>"
            for row in parsed
        )
        vuln_html = f"""
        <h3>Vulnerabilities ({len(parsed)})</h3>
        <table class="nessus-table">
          <thead><tr><th>Sev</th><th>CVSS</th><th>VPR</th><th>EPSS</th>
          <th>Name</th><th>Family</th><th>Count</th></tr></thead>
          <tbody>{rows_html}</tbody>
        </table>"""

    img_tag = f"<img class='shot' src='../screens/{html_lib.escape(screenshot_name)}'>" if screenshot_name else ""

    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>{html_lib.escape(host_title)}</title>
<style>
:root{{--bg:#1e2226;--panel:#2b3136;--muted:#b6c0c6;--line:#3a4046;--accent:#9dc7ff}}
body{{margin:0;background:var(--bg);color:#e7eef6;font-family:Inter,Roboto,Arial,sans-serif}}
.container{{max-width:1200px;margin:24px auto;padding:18px}}
.host-card{{background:var(--panel);padding:14px;border-radius:8px;margin-bottom:18px}}
.host-title{{font-size:20px;margin-bottom:6px;color:var(--accent)}}
.meta{{color:var(--muted);font-size:13px;margin-bottom:8px}}
.nessus-table{{width:100%;border-collapse:collapse;font-size:13px}}
.nessus-table th,.nessus-table td{{padding:9px;border-bottom:1px solid var(--line)}}
.nessus-table th{{background:#262a2f;text-align:left}}
.nessus-table tr:nth-child(even){{background:#293034}}
.nessus-table tr:hover{{background:#33383f}}
.shot{{width:100%;border-radius:6px;margin-bottom:12px;box-shadow:0 0 8px #0005}}
</style></head><body>
<div class="container">
  <div class="host-card">
    <div class="host-title">{html_lib.escape(host_title)}</div>
    <div class="meta">Offline snapshot — Overview + Vulnerabilities</div>
    {img_tag}
    {vuln_html}
  </div>
</div>
</body></html>"""


# ---------------- Fetch one host ----------------
async def worker_fetch(page, url, out_pages: Path, out_screens: Path, do_screenshots: bool):
    try:
        await page.goto(url, wait_until="networkidle", timeout=45000)
    except Exception:
        await page.wait_for_timeout(1500)

    title = None
    for sel in ["h1", ".page-header h1", ".view-title h1"]:
        try:
            el = await page.query_selector(sel)
            if el:
                t = (await el.inner_text()).strip()
                if t:
                    title = t
                    break
        except Exception:
            pass

    if not title:
        html = await page.content()
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", html)
        title = m.group(1) if m else url.split("/")[-1]

    key = re.sub(r"[^0-9A-Za-z_\-]", "_", title)
    png_name = None
    if do_screenshots:
        png_path = out_screens / f"{key}.png"
        try:
            await page.screenshot(path=str(png_path), full_page=True)
            png_name = png_path.name
        except Exception:
            png_name = None

    html_clean = clean_vuln_table_from_html(await page.content(), title, png_name)
    html_path = out_pages / f"{key}.html"
    html_path.write_text(html_clean, encoding="utf-8")

    return url, key, title, html_path.name, png_name


# ---------------- Login helper ----------------
async def try_login(page, start_url, user, passwd):
    try:
        await page.goto(start_url, wait_until="load", timeout=25000)
    except Exception:
        pass
    for u_sel, p_sel in [
        ("input[name='username']", "input[name='password']"),
        ("input[id*='user']", "input[id*='pass']"),
        ("input[type='text']", "input[type='password']"),
    ]:
        try:
            u = await page.query_selector(u_sel)
            p = await page.query_selector(p_sel)
            if u and p:
                await u.fill(user)
                await p.fill(passwd)
                await p.press("Enter")
                await page.wait_for_timeout(3000)
                return True
        except Exception:
            continue
    return False


# ---------------- Main async crawl ----------------
async def main_async(args):
    out = Path(args.out)
    pages_dir = out / "pages"
    screens_dir = out / "screens"
    pages_dir.mkdir(parents=True, exist_ok=True)
    if args.screenshots:
        screens_dir.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as pw:
        browser = await pw.firefox.launch(headless=True)
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()

        if args.user and args.passw:
            print("[*] Attempting login ...")
            ok = await try_login(page, args.start, args.user, args.passw)
            print(f"[+] Login attempted: {'success' if ok else 'skipped/failed'}")
        else:
            await page.goto(args.start, wait_until="load")

        print("[*] Collecting host URLs ...")
        await page.wait_for_timeout(3000)

        urls = set()

        # 1️⃣ JS-basierte Links
        try:
            js_links = await page.evaluate("""() => {
                const anchors = Array.from(document.querySelectorAll('a'));
                return anchors.map(a => a.href).filter(h => h && h.includes('/hosts/') && h.includes('/vulnerabilities'));
            }""")
            urls.update(js_links)
        except Exception:
            pass

        # 2️⃣ HTML-basierte Links
        html_src = await page.content()
        html_links = re.findall(r'href=["\']([^"\']*?/hosts/[^"\']*?/vulnerabilities[^"\']*)["\']', html_src)
        urls.update(html_links)

        # 3️⃣ Fallback: IDs direkt im HTML
        if not urls:
            host_ids = re.findall(r'data-id=["\'](\d+)["\']', html_src)
            if host_ids:
                m = re.search(r'#/scans/reports/(\d+)', args.start)
                report_id = m.group(1) if m else "8"
                origin = f"{urlparse(args.start).scheme}://{urlparse(args.start).netloc}"
                for hid in sorted(set(host_ids)):
                    urls.add(f"{origin}/#/scans/reports/{report_id}/hosts/{hid}/vulnerabilities")

        urls = sorted(urls)
        print(f"[+] Found {len(urls)} vulnerability URLs to process.")

        results = []
        sem = Semaphore(args.threads)

        async def task(u):
            async with sem:
                p = await ctx.new_page()
                try:
                    res = await worker_fetch(p, u, pages_dir, screens_dir, args.screenshots)
                    results.append(res)
                    print(f"[✓] {res[2]}")
                except Exception as e:
                    print(f"[!] Error {u}: {e}")
                finally:
                    await p.close()

        await asyncio.gather(*(task(u) for u in urls))
        await browser.close()

    build_index_html(out, results, args.start)
    print(f"[✔] Done. Output in: {out}")


# ---------------- Index builder ----------------
def sort_ip_key(name):
    ip = re.findall(r"(\d+\.\d+\.\d+\.\d+)", name)
    try:
        return ipaddress.ip_address(ip[0]) if ip else ipaddress.ip_address("0.0.0.0")
    except:
        return ipaddress.ip_address("0.0.0.0")


def build_index_html(out_dir: Path, results, scan_url):
    out_pages = out_dir / "pages"
    out_screens = out_dir / "screens"

    # 🧠 Fallback für --build-website: bestehende Detailseiten analysieren
    if not results:
        files = sorted(out_pages.glob("*.html"), key=lambda x: sort_ip_key(x.name))
        results = []
        for f in files:
            base = f.stem
            content = f.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"<img[^>]+src=['\"]\.\./screens/([^'\"]+)['\"]", content)
            png_name = m.group(1) if m else None
            results.append((None, base, base, f.name, png_name))

    html = [f"""<!doctype html><html lang='en'><head>
<meta charset='utf-8'><title>Nessus Offline Clone</title>
<style>
:root{{--bg:#1b1f23;--panel:#242a2f;--mut:#9fb0c8;--acc:#9dc7ff}}
body{{margin:0;font-family:Inter,Roboto,Arial,sans-serif;background:var(--bg);color:#e6eef6}}
.top{{background:#2b3035;padding:12px 18px;display:flex;align-items:center;gap:18px}}
.brand{{font-weight:700;color:var(--acc)}}
.grid{{display:grid;gap:18px;padding:18px;grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}}
.card{{background:var(--panel);padding:12px;border-radius:8px}}
.thumb{{width:100%;height:160px;object-fit:cover;border-radius:6px;background:#15191d}}
.title{{font-weight:600;margin:6px 0;color:var(--acc)}}
.meta{{font-size:13px;color:var(--mut)}}
a.small{{color:var(--acc);text-decoration:none}}
</style></head><body>
<div class='top'><div class='brand'>Nessus Offline Clone</div>
<div style='font-size:13px;color:#9fb0c8'>Snapshot of scan: {html_lib.escape(scan_url)}</div></div>
<div class='grid'>"""]

    for (_, _, title, html_name, png_name) in results:
        thumb_path = f"screens/{png_name}" if png_name and (out_screens / png_name).exists() else ""
        html.append(f"""
<div class='card'>
  <a href='pages/{html_name}'><img class='thumb' src='{thumb_path}'></a>
  <div class='title'>{html_lib.escape(title)}</div>
  <div class='meta'><a class='small' href='pages/{html_name}'>Open host report</a></div>
</div>""")

    html.append("</div></body></html>")
    (out_dir / "index.html").write_text("\n".join(html), encoding="utf-8")
    print(f"[✓] index.html written to {out_dir / 'index.html'}")


# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--start", help="Start URL (e.g. https://127.0.0.1:8834/#/scans/reports/8/hosts)")
    p.add_argument("--user", help="Username")
    p.add_argument("--passw", help="Password")
    p.add_argument("--out", default="./saved", help="Output directory")
    p.add_argument("--threads", type=int, default=4, help="Concurrent workers")
    p.add_argument("--screenshots", action="store_true", help="Save screenshots")
    p.add_argument("--build-website", action="store_true", help="Only rebuild index.html from existing files")
    return p.parse_args()


def main():
    args = parse_args()
    out = Path(args.out)
    if args.build_website:
        build_index_html(out, [], args.start or "local files")
    else:
        if async_playwright is None:
            raise SystemExit("Playwright not installed. Run: pip install playwright && playwright install firefox")
        try:
            asyncio.run(main_async(args))
        except KeyboardInterrupt:
            print("\n[!] Aborted by user")


if __name__ == "__main__":
    main()

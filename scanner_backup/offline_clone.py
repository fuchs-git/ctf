#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nessus_clone_allinone.py
Single-file tool to:
 - login to local Nessus (optional)
 - collect per-host Overview + Vulnerabilities pages
 - save cleaned HTML per host and optional screenshots
 - produce index.html with links + thumbnails

Usage example:
 python3 nessus_clone_allinone.py \
   --start "https://127.0.0.1:8834/#/scans/reports/8/hosts" \
   --user "ioi_sec" --passw "ioi_sec" --out ./saved --threads 8 --screenshots
"""

import argparse
import asyncio
import re
import html as html_lib
from pathlib import Path
from urllib.parse import urlparse
from asyncio import Semaphore

# Playwright async
try:
    from playwright.async_api import async_playwright
except Exception as e:
    raise SystemExit("playwright is required. Install with: pip install playwright && playwright install firefox") from e


# -------------------------
# Utilities / HTML cleaning
# -------------------------
def clean_vuln_table_from_html(src_html: str, host_title: str) -> str:
    """
    Extract rows with class 'vulnerability' and build a clean HTML page with a styled table.
    If no rows found, write a short 'no vulnerabilities' message.
    """
    # Find <tr ... class="...vulnerability..."> ... </tr>
    rows = re.findall(r'(?is)<tr[^>]*class=["\'][^"\']*vulnerability[^"\']*["\'][^>]*>(.*?)</tr>', src_html)
    parsed = []
    for row_html in rows:
        tds = re.findall(r'(?is)<td[^>]*>(.*?)</td>', row_html)
        # strip tags from each td
        cells = [re.sub(r'(?is)<.*?>', '', td).strip() for td in tds]
        if not cells:
            continue
        # ensure at least 7 cols for consistent layout
        while len(cells) < 7:
            cells.append("")
        parsed.append(cells[:7])

    if not parsed:
        vuln_html = "<p><em>No vulnerabilities found for this host.</em></p>"
    else:
        head = "<tr><th>Sev</th><th>CVSS</th><th>VPR</th><th>EPSS</th><th>Name</th><th>Family</th><th>Count</th></tr>"
        body_rows = "\n".join(
            "<tr>" + "".join(f"<td>{html_lib.escape(cell)}</td>" for cell in row) + "</tr>"
            for row in parsed
        )
        vuln_html = f"""
        <h3>Vulnerabilities ({len(parsed)})</h3>
        <div style="overflow:auto">
        <table class="nessus-table">
          <thead>{head}</thead>
          <tbody>
            {body_rows}
          </tbody>
        </table>
        </div>
        """

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html_lib.escape(host_title)}</title>
<style>
:root{{--bg:#1e2226;--panel:#2b3136;--muted:#b6c0c6;--line:#3a4046;--accent:#9dc7ff}}
html,body{{margin:0;padding:0;background:var(--bg);color:#e7eef6;font-family:Inter,Roboto,Arial,Helvetica,sans-serif;}}
.container{{max-width:1200px;margin:24px auto;padding:18px;}}
.host-card{{background:var(--panel);padding:14px;border-radius:8px;margin-bottom:18px;}}
.host-title{{font-size:20px;margin:0 0 8px 0;color:var(--accent)}}
.meta{{color:var(--muted);font-size:13px;margin-bottom:8px}}
.nessus-table{{width:100%;border-collapse:collapse;font-size:13px}}
.nessus-table thead th{{background:#262a2f;padding:10px;border-bottom:1px solid var(--line);text-align:left}}
.nessus-table td{{padding:9px;border-bottom:1px solid var(--line)}}
.nessus-table tbody tr:nth-child(even){{background:#293034}}
.nessus-table tbody tr:hover{{background:#33383f}}
</style>
</head>
<body>
  <div class="container">
    <div class="host-card">
      <div class="host-title">{html_lib.escape(host_title)}</div>
      <div class="meta">Offline snapshot — Overview + Vulnerabilities</div>
      {vuln_html}
    </div>
  </div>
</body>
</html>"""
    return page


# -------------------------
# Main async worker
# -------------------------
async def worker_fetch(page, url, out_pages: Path, out_screens: Path, do_screenshots: bool):
    """
    Navigate to url (vulnerabilities view), extract a host title (IP/name), save cleaned HTML and optional screenshot.
    Returns tuple (host_key, title, html_filename, png_filename_or_None)
    """
    try:
        await page.goto(url, wait_until="networkidle", timeout=45000)
    except Exception:
        # try load anyway
        try:
            await page.wait_for_timeout(2000)
        except Exception:
            pass

    # attempt to get title from common selectors
    title = None
    candidates = [
        "h1", ".title-box h1", ".page-header h1", ".view-title h1", ".host-header h1",
        "header h1"
    ]
    for sel in candidates:
        try:
            el = await page.query_selector(sel)
            if el:
                txt = (await el.inner_text()).strip()
                if txt:
                    title = txt
                    break
        except Exception:
            continue

    # fallback: try to extract IP in page
    if not title:
        content = await page.content()
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", content)
        if m:
            title = m.group(1)
        else:
            # fallback to last path element
            parsed = urlparse(url)
            title = parsed.path.split("/")[-1] or parsed.path

    # sanitize key
    key = re.sub(r'[^0-9A-Za-z_\-]', '_', title)

    content = await page.content()
    cleaned = clean_vuln_table_from_html(content, title)
    html_path = out_pages / f"{key}.html"
    html_path.write_text(cleaned, encoding="utf-8")

    png_path = None
    if do_screenshots:
        try:
            png_path = out_screens / f"{key}.png"
            await page.screenshot(path=str(png_path), full_page=True)
        except Exception as e:
            png_path = None

    return key, title, html_path.name, png_path.name if png_path else None


# -------------------------
# Login helper
# -------------------------
async def try_login(page, start_url, user, passwd):
    """
    Try multiple strategies to login to Nessus UI:
    - common inputs (username/password)
    - token fields if present
    If fails, continue without exception (we may already be logged in).
    """
    try:
        await page.goto(start_url, wait_until="load", timeout=30000)
    except Exception:
        pass

    # common selectors
    login_attempts = [
        # classic form fields
        {"user": "input[type='text'][name*='user']", "pass": "input[type='password']"},
        {"user": "input[id*='user']", "pass": "input[id*='pass']"},
        {"user": "input[name='username']", "pass": "input[name='password']"},
        {"user": "input[type='text']", "pass": "input[type='password']"},
    ]
    for sel in login_attempts:
        try:
            uel = await page.query_selector(sel["user"])
            pel = await page.query_selector(sel["pass"])
            if uel and pel:
                await uel.fill(user)
                await pel.fill(passwd)
                # press enter either on password field or find submit
                try:
                    await pel.press("Enter")
                except Exception:
                    pass
                # wait a bit for navigation
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    await page.wait_for_timeout(1500)
                return True
        except Exception:
            continue

    # no form found; maybe token/cookie-based — do nothing
    return False


# -------------------------
# Entry point
# -------------------------
async def main_async(args):
    out_base = Path(args.out).resolve()
    out_pages = out_base / "pages"
    out_screens = out_base / "screens"
    out_base.mkdir(parents=True, exist_ok=True)
    out_pages.mkdir(parents=True, exist_ok=True)
    if args.screenshots:
        out_screens.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as pw:
        # use headless firefox (works well for many setups)
        browser = await pw.firefox.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True, viewport={"width": 1400, "height": 900})
        page = await context.new_page()

        # optional login
        if args.user and args.passw:
            print("[*] Attempting login ...")
            ok = await try_login(page, args.start, args.user, args.passw)
            print(f"[+] Login attempted: {'success/found-login' if ok else 'no-login-found-or-already-logged-in'}")
        else:
            # navigate to start URL to ensure we have content to parse
            try:
                await page.goto(args.start, wait_until="load", timeout=25000)
            except Exception:
                pass

        # --- gather candidate vulnerability URLs ---
        print("[*] Collecting host vulnerability links ...")
        try:
            # execute JS in page to collect links with '/hosts/' and '/vulnerabilities'
            await page.goto(args.start, wait_until="networkidle", timeout=30000)
        except Exception:
            # continue - maybe already on page
            pass

        page_content = await page.content()
        # try to find absolute links
        hrefs = set(re.findall(r'href=["\']([^"\']*?/hosts/[^"\']*?/vulnerabilities[^"\']*)["\']', page_content))
        # if not absolute, try search for hash fragments
        if not hrefs:
            # matches like #/scans/reports/8/hosts/9/vulnerabilities
            hash_hrefs = set(re.findall(r'(#/scans/reports/\d+/hosts/\d+/vulnerabilities[^"\s>]*)', page_content))
            # make absolute based on start URL origin
            origin = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(args.start))
            for h in hash_hrefs:
                if h.startswith("#"):
                    hrefs.add(origin + "/" + h.lstrip("#/"))
                else:
                    hrefs.add(origin + h)
        # also attempt to gather via JS (if page has links rendered by JS)
        if not hrefs:
            try:
                js_links = await page.evaluate("""() => {
                    const list = Array.from(document.querySelectorAll('a'));
                    return list.map(a => a.href).filter(h => h && h.includes('/hosts/') && h.includes('vulnerabilities'));
                }""")
                for l in js_links:
                    hrefs.add(l)
            except Exception:
                pass

        # normalise hrefs and keep those that look like vulnerabilities pages
        normalized = []
        for h in hrefs:
            if not h:
                continue
            # if starts with '#', make absolute
            if h.startswith("#"):
                base = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(args.start))
                h = base + "/" + h.lstrip("#/")
            normalized.append(h)
        unique_urls = sorted(set(normalized))
        if not unique_urls:
            # fallback: try constructing using path pattern - find hosts by IDs in page
            host_ids = re.findall(r'data-id=["\'](\d+)["\']', page_content)
            if host_ids:
                for hid in sorted(set(host_ids)):
                    # assemble URL
                    m = re.search(r'#/scans/reports/(\d+)', args.start)
                    report_id = m.group(1) if m else "8"
                    base = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(args.start))
                    unique_urls.append(f"{base}/#/scans/reports/{report_id}/hosts/{hid}/vulnerabilities")
        print(f"[+] Found {len(unique_urls)} vulnerability URLs to process.")

        # concurrency semaphore
        sem = Semaphore(args.threads)

        results = []

        async def bounded_worker(url):
            async with sem:
                # each worker uses its own new page (avoids greenlet/threading issues)
                p = await context.new_page()
                try:
                    res = await worker_fetch(p, url, out_pages, out_screens, args.screenshots)
                    results.append((url, *res))
                    print(f"[✓] Saved {res[1]} ({res[0]})")
                except Exception as e:
                    print(f"[!] Error fetching {url}: {e}")
                finally:
                    try:
                        await p.close()
                    except Exception:
                        pass

        # schedule all workers
        tasks = [asyncio.create_task(bounded_worker(u)) for u in unique_urls]
        # wait for completion
        await asyncio.gather(*tasks)

        await context.close()
        await browser.close()

    # ---------------------
    # build index.html
    # ---------------------
    print("[*] Building index.html ...")
    index_lines = []
    # --- Fix for KeyError: '--bg' ---
# Replace the affected style block (Zeile ~340) mit:

    index_lines.append("""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Nessus Offline Clone</title>
<style>
:root{{--bg:#1c2024;--panel:#2b3136;--muted:#9fb0c8;--accent:#9dc7ff}}
body{{margin:0;font-family:Inter,Roboto,Arial,sans-serif;background:var(--bg);color:#e6eef6}}
.top{{background:#2d3338;padding:12px 18px;display:flex;align-items:center;gap:18px}}
.brand{{font-weight:700;color:var(--accent)}}
.wrap{{display:flex;height:calc(100vh - 54px)}}
.sidebar{{width:260px;background:#23282d;padding:10px;overflow:auto}}
.main{{flex:1;padding:18px;overflow:auto}}
.host-link{{display:block;padding:8px 6px;color:#b7c8dd;text-decoration:none;border-bottom:1px solid #272c31}}
.host-link:hover{{background:#2f353a}}
.grid{{display:grid;grid-template-columns: repeat(auto-fill,minmax(320px,1fr));gap:16px}}
.card{{background:var(--panel);padding:12px;border-radius:8px}}
.thumb{{width:100%;height:160px;object-fit:cover;border-radius:4px;background:#17191c}}
.title{{font-weight:600;color:var(--accent);margin:6px 0}}
.meta{{font-size:13px;color:var(--muted)}}
a.small{{color:#9dc7ff;font-size:13px}}
</style></head><body>
<div class="top"><div class="brand">Nessus Offline Clone</div><div style="color:#9fb0c8">Snapshot of scan: {scan_link}</div></div>
<div class="wrap"><div class="sidebar">""".format(scan_link=html_lib.escape(args.start)))

    # sidebar with list of hosts
    for (_, key, title, html_name, png_name) in results:
        index_lines.append(f'<a class="host-link" href="pages/{html_name}">{html_lib.escape(title)}</a>')
    index_lines.append("</div><div class='main'><div class='grid'>")
    # main cards
    for (_, key, title, html_name, png_name) in results:
        thumb_html = f'<img class="thumb" src="screens/{png_name}">' if (png_name and (out_base / "screens" / png_name).exists()) else '<div class="thumb"></div>'
        index_lines.append(f"""
        <div class="card">
          <a class="small" href="pages/{html_name}">{thumb_html}</a>
          <div class="title"><a class="small" href="pages/{html_name}">{html_lib.escape(title)}</a></div>
          <div class="meta">Host page: <a class="small" href="pages/{html_name}">pages/{html_name}</a></div>
        </div>
        """)

    index_lines.append("</div></div></div></body></html>")
    (out_base / "index.html").write_text("\n".join(index_lines), encoding="utf-8")
    print(f"[✔] Done. Files written to {out_base}. Open {out_base / 'index.html'} with your browser.")


# -------------------------
# CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(prog="nessus_clone_allinone.py")
    p.add_argument("--start", required=True, help="Start URL (e.g. https://127.0.0.1:8834/#/scans/reports/8/hosts)")
    p.add_argument("--user", help="Username for login (optional)")
    p.add_argument("--passw", help="Password for login (optional)")
    p.add_argument("--out", default="./saved", help="Output dir (default ./saved)")
    p.add_argument("--threads", type=int, default=4, help="Concurrent workers (default 4)")
    p.add_argument("--screenshots", action="store_true", help="Also capture screenshots to OUT/screens")
    return p.parse_args()


def main():
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")


if __name__ == "__main__":
    main()


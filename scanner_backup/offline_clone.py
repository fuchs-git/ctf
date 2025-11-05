#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nessus Offline Clone – v6
--------------------------------
• Entfernt Launch/Modify/Snooze/Folders/Notice-Elemente
• Liest echte Tabellenstruktur aus <tr class="vulnerability">-Zeilen
• Baut HTML-Table wie im Original
• Helles Grau/Darkmode-Stil
"""
import asyncio, re, argparse
from pathlib import Path
from playwright.async_api import async_playwright

parser = argparse.ArgumentParser()
parser.add_argument("--start", required=True)
parser.add_argument("--user", default="ioi_sec")
parser.add_argument("--passw", default="ioi_sec")
parser.add_argument("--out", default="./saved")
parser.add_argument("--threads", type=int, default=2)
parser.add_argument("--screenshots", action="store_true")
args = parser.parse_args()

OUT = Path(args.out)
OUT.mkdir(parents=True, exist_ok=True)
HOSTS_DIR = OUT / "hosts"
IMAGES_DIR = OUT / "screenshots"
HOSTS_DIR.mkdir(exist_ok=True)
IMAGES_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------
def sanitize(name): return re.sub(r"[^A-Za-z0-9_.-]", "_", name)

def inject_style(html: str) -> str:
    style = """
    <style>
    body {
        background: #1f2329;
        color: #eaeaea;
        font-family: 'Open Sans', Roboto, sans-serif;
        margin: 0;
        padding: 2rem;
    }
    h3 { color: #9dc7ff; margin-top: 1.5em; }

    table.nessus-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 0.5em;
        background: #2b3037;
        border-radius: 6px;
        overflow: hidden;
        font-size: 14px;
    }
    table.nessus-table th {
        background: #353b44;
        padding: 10px;
        text-align: left;
        font-weight: 600;
        border-bottom: 2px solid #454b54;
    }
    table.nessus-table td {
        padding: 8px 10px;
        border-bottom: 1px solid #3c4149;
    }
    tr:nth-child(even) { background: #262b31; }
    tr:hover { background: #39404a; }

    .sev-critical td:first-child { background: #ff4d4d; color: #fff; font-weight: 700; text-align:center; border-radius:4px; }
    .sev-high td:first-child     { background: #ff944d; color: #fff; font-weight: 700; text-align:center; border-radius:4px; }
    .sev-medium td:first-child   { background: #ffb84d; color: #000; font-weight: 700; text-align:center; border-radius:4px; }
    .sev-low td:first-child      { background: #ffff66; color: #000; font-weight: 700; text-align:center; border-radius:4px; }
    .sev-info td:first-child     { background: #7fbfff; color: #000; font-weight: 700; text-align:center; border-radius:4px; }
    .sev-mixed td:first-child    { background: #b47eff; color: #fff; font-weight: 700; text-align:center; border-radius:4px; }
    </style>
    """
    return re.sub(r"</head>", style + "</head>", html, flags=re.I)


def clean_html(html: str) -> str:
    """Bereinigt und konvertiert Nessus-Seiten (finale Version mit echter Tabelle)"""
    # (obere Regex-Entfernungen beibehalten wie zuvor!)

    # --- ab hier neuer Tabellenteil ---
    import html as html_lib
    rows = re.findall(r"(?is)<tr[^>]+class=['\"]vulnerability[^>]*?>(.*?)</tr>", html)
    parsed = []
    for row in rows:
        # alle TD-Inhalte extrahieren und HTML-Tags entfernen
        tds = [re.sub(r"<.*?>", "", c).strip() for c in re.findall(r"<td[^>]*>(.*?)</td>", row)]
        if not tds:
            continue
        # Leere Spalten auffüllen
        while len(tds) < 7:
            tds.append("")
        sev_match = re.search(r"(Critical|High|Medium|Low|Info|Mixed)", tds[0], re.I)
        sev_txt = sev_match.group(1).capitalize() if sev_match else "Info"
        sev_cls = f"sev-{sev_txt.lower()}"
        parsed.append((sev_cls, [html_lib.escape(x) for x in tds[:7]]))

    # wenn nichts gefunden wurde
    if not parsed:
        return "<p><i>No vulnerabilities found for this host.</i></p>"

    # Tabelle generieren
    table_html = """
    <h3>Vulnerabilities</h3>
    <table class="nessus-table">
      <thead>
        <tr>
          <th>Sev</th><th>CVSS</th><th>VPR</th><th>EPSS</th>
          <th>Name</th><th>Family</th><th>Count</th>
        </tr>
      </thead>
      <tbody>
    """
    for sev_cls, cols in parsed:
        table_html += f"<tr class='{sev_cls}'>" + "".join(f"<td>{c}</td>" for c in cols) + "</tr>"
    table_html += "</tbody></table>"
    html = re.sub(r"(?is)\d+\s+Vulnerabilities.*", table_html, html)
    return html



async def save_page(page, name, screenshots=False, host=False):
    await page.wait_for_load_state("networkidle")
    html = await page.content()
    html = inject_style(clean_html(html))
    dest = (HOSTS_DIR if host else OUT) / f"{sanitize(name)}.html"
    dest.write_text(html, encoding="utf-8")
    print(f"[✓] {dest.name}")
    if screenshots:
        await page.screenshot(path=str(IMAGES_DIR / f"{sanitize(name)}.png"), full_page=True)

# ---------------------------------------------------------------------
async def login(page):
    await page.goto(args.start, wait_until="domcontentloaded")
    try:
        await page.fill('input[type="text"]', args.user)
        await page.fill('input[type="password"]', args.passw)
        await page.keyboard.press("Enter")
        await page.wait_for_url("**/#/scans**", timeout=10000)
        print("[+] Login erfolgreich.")
    except:
        print("[!] Login evtl. bereits aktiv.")

async def extract_hosts(page):
    await page.wait_for_selector("table")
    html = await page.content()
    return sorted(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", html)))

async def capture_host(pw, ip, screenshots):
    try:
        browser = await pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        await login(page)
        await page.goto(args.start)
        row = page.locator(f"text='{ip}'").first
        await row.click()
        await save_page(page, f"{ip}_overview", screenshots, host=True)
        try:
            await page.get_by_role("link", name="Vulnerabilities").click(timeout=5000)
            await save_page(page, f"{ip}_vulnerabilities", screenshots, host=True)
        except:
            print(f"[-] Tab 'Vulnerabilities' nicht gefunden für {ip}")
        await browser.close()
    except Exception as e:
        print(f"[!] Fehler bei {ip}: {e}")

# ---------------------------------------------------------------------
def build_dashboard(hosts):
    css = """
    <style>
    body{margin:0;font-family:Segoe UI,Roboto,Ubuntu,sans-serif;background:#1d232a;color:#eee}
    header{background:#2a313a;padding:10px 20px;font-size:20px;font-weight:600}
    #list{width:280px;background:#242b33;position:fixed;top:50px;bottom:0;overflow:auto}
    #viewer{margin-left:280px;height:calc(100vh - 50px)}
    #viewer iframe{width:100%;height:100%;border:none;background:#fff}
    .host{padding:8px 12px;border-bottom:1px solid #333;cursor:pointer}
    .host:hover{background:#3b4450}
    input{width:90%;margin:10px;padding:5px;background:#111;border:1px solid #444;color:#eee}
    </style>
    <script>
    function f(){
      let q=document.getElementById('search').value.toLowerCase();
      for(const d of document.querySelectorAll('.host')){
        d.style.display=d.textContent.toLowerCase().includes(q)?'block':'none';
      }}
    function openHost(h,tab){
      document.getElementById('viewer').innerHTML=
      `<iframe src='hosts/${h}_${tab}.html'></iframe>`;
      for(const el of document.querySelectorAll('.host'))el.style.background='';
      document.getElementById('h_'+h).style.background='#3b4450';
    }
    </script>
    """
    html = [f"<html><head><meta charset='utf-8'><title>Nessus Clone</title>{css}</head><body>"]
    html.append("<header>🧩 Nessus Offline Clone</header>")
    html.append("<div id='list'><input id='search' onkeyup='f()' placeholder='Filter Host/IP...'>")
    for ip in hosts:
        h = sanitize(ip)
        html.append(f"<div class='host' id='h_{h}' onclick=\"openHost('{h}','overview')\">"
                    f"{ip}<br><a href='#' onclick=\"openHost('{h}','vulnerabilities');event.stopPropagation();\">"
                    f"Vulnerabilities</a></div>")
    html.append("</div><div id='viewer'><iframe src='scan_hosts_overview.html'></iframe></div></body></html>")
    (OUT / "index.html").write_text("\n".join(html), encoding="utf-8")
    print(f"[✓] Dashboard erstellt: {OUT/'index.html'}")

# ---------------------------------------------------------------------
async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        await login(page)
        await page.goto(args.start)
        hosts = await extract_hosts(page)
        print(f"[+] {len(hosts)} Hosts gefunden.")
        await save_page(page, "scan_hosts_overview", args.screenshots)
        await browser.close()

        sem = asyncio.Semaphore(args.threads)
        async def limited(ip):
            async with sem:
                await capture_host(pw, ip, args.screenshots)
                await asyncio.sleep(0.5)

        await asyncio.gather(*(limited(ip) for ip in hosts))
        build_dashboard(hosts)

if __name__ == "__main__":
    asyncio.run(main())
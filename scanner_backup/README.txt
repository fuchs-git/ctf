cd ~/nessus_clone       # oder dein Projektordner
python3 -m venv .venv   # virtuelle Umgebung anlegen
source .venv/bin/activate
pip install --upgrade pip
pip install playwright
playwright install firefox   # oder chromium

python3 nessus_clone.py --start "https://127.0.0.1:8834/#/scans/reports/8/hosts" --user "ioi_sec" --passw "ioi_sec" --out ./saved --threads 8 --screenshots


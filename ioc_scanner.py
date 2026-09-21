#!/usr/bin/env python3
"""
Simple iPhone IOC Scanner
--------------------------
1. Plug in your iPhone and trust this computer
2. Script backs up your phone automatically
3. Script grabs sysdiagnose logs from your phone
4. Script captures live network traffic for 60 seconds
5. Paste your IOCs when prompted
6. Script checks everything and tells you if anything matched
"""

import os
import sys
import time
import sqlite3
import hashlib
import subprocess
import shutil
import re
import json
import urllib.request
from pathlib import Path
from datetime import datetime


# ══════════════════════════════════════════════════════
#  STEP 1 — GET PHONE UDID
# ══════════════════════════════════════════════════════

def get_udid():
    print("\n[1] Checking for connected iPhone...")

    if not shutil.which("idevice_id"):
        print("    ERROR: libimobiledevice not found.")
        print("    Install it with:  brew install libimobiledevice")
        exit()

    result = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True)
    udid   = result.stdout.strip()

    if not udid:
        print("    ERROR: No iPhone detected.")
        print("    Make sure your phone is plugged in and you tapped Trust.")
        exit()

    print(f"    Phone found: {udid}")
    return udid


# ══════════════════════════════════════════════════════
#  STEP 2 — BACK UP THE PHONE
# ══════════════════════════════════════════════════════

def backup_phone(udid):
    print("\n[2] Backing up iPhone...")

    if not shutil.which("idevicebackup2"):
        print("    ERROR: idevicebackup2 not found.")
        print("    Install it with:  brew install libimobiledevice")
        exit()

    backup_folder = Path.home() / "iphone_scan" / "backup"
    backup_folder.mkdir(parents=True, exist_ok=True)
    print(f"    Saving backup to: {backup_folder}")
    print("    This may take a few minutes...\n")

    # Check if a previous backup exists
    backup_exists = (backup_folder / udid).exists()

    if backup_exists:
        print("    Previous backup found — running incremental backup...")
        print("    Only new and changed files will be copied.\n")
        subprocess.run([
            "idevicebackup2",
            "-u", udid,
            "backup",          # no --full = incremental
            str(backup_folder)
        ])
    else:
        print("    No previous backup found — running full backup...")
        print("    This may take a few minutes on first run.\n")
        subprocess.run([
            "idevicebackup2",
            "-u", udid,
            "backup",
            "--full",
            str(backup_folder)
        ])

    backup_path = backup_folder / udid
    if not backup_path.exists():
        print("    ERROR: Backup folder not found after backup.")
        print("    Make sure encrypted backup is turned OFF in Finder.")
        exit()

    print(f"    Backup complete: {backup_path}")
    return backup_path


# ══════════════════════════════════════════════════════
#  STEP 3 — GRAB SYSDIAGNOSE LOGS
# ══════════════════════════════════════════════════════

def grab_sysdiagnose(udid):
    print("\n[3] Grabbing sysdiagnose logs from iPhone...")

    if not shutil.which("idevicecrashreport"):
        print("    SKIP: idevicecrashreport not found.")
        print("    Install it with:  brew install libimobiledevice")
        return None

    sysdiag_folder = Path.home() / "iphone_scan" / "sysdiagnose"
    sysdiag_folder.mkdir(parents=True, exist_ok=True)

    print("    Pulling crash reports and system logs...")
    subprocess.run([
        "idevicecrashreport",
        "-u", udid,
        "-e",
        "-k",
        str(sysdiag_folder)
    ], capture_output=True, text=True)

    files = list(sysdiag_folder.rglob("*"))
    if not files:
        print("    NOTE: No logs found on device right now.")
        print("    To trigger sysdiagnose manually:")
        print("    Hold Volume Up + Volume Down + Power for 1-2 seconds")
        return None

    print(f"    Got {len(files)} log files  ->  {sysdiag_folder}")
    return sysdiag_folder


# ══════════════════════════════════════════════════════
#  STEP 4 — CAPTURE LIVE NETWORK TRAFFIC
# ══════════════════════════════════════════════════════

def capture_traffic(udid):
    print("\n[4] Capturing live network traffic (rvictl + tcpdump)...")

    if not shutil.which("rvictl"):
        print("    SKIP: rvictl not found. Install Xcode from the App Store.")
        return None

    if not shutil.which("tcpdump"):
        print("    SKIP: tcpdump not found.")
        return None

    pcap_folder = Path.home() / "iphone_scan" / "traffic"
    pcap_folder.mkdir(parents=True, exist_ok=True)
    pcap_file = pcap_folder / "iphone_traffic.pcap"

    # Remove old pcap before starting fresh
    if pcap_file.exists():
        pcap_file.unlink()
        print("    Removed old pcap file.")

    # Start rvictl
    print("    Starting rvictl virtual interface for your phone...")
    subprocess.run(["rvictl", "-s", udid], capture_output=True)

    # Wait for rvi0 to be fully ready
    print("    Waiting for rvi0 interface to become ready...")
    time.sleep(5)

    # Verify rvi0 is up
    check = subprocess.run(["ifconfig", "rvi0"], capture_output=True, text=True)
    if "rvi0" not in check.stdout:
        print("    ERROR: rvi0 interface did not come up.")
        subprocess.run(["rvictl", "-x", udid], capture_output=True)
        return None

    print("    rvi0 interface is ready.")

    duration = 60
    print(f"    Capturing traffic for {duration} seconds...")
    print("    Use your phone normally now (open apps, browse, etc.)\n")

    try:
        proc = subprocess.Popen([
            "sudo", "tcpdump",
            "-i", "rvi0",
            "-p",
            "-n",
            "-s", "65535",
            "-w", str(pcap_file),
        ])

        for remaining in range(duration, 0, -10):
            print(f"    {remaining} seconds remaining...")
            time.sleep(10)

        import signal
        proc.send_signal(signal.SIGINT)
        proc.wait()
        time.sleep(2)

    except KeyboardInterrupt:
        print("\n    Capture stopped early.")
        import signal
        proc.send_signal(signal.SIGINT)
        proc.wait()
        time.sleep(2)

    finally:
        subprocess.run(["rvictl", "-x", udid], capture_output=True)
        print("    rvictl interface stopped.")

    if pcap_file.exists() and pcap_file.stat().st_size > 100:
        print(f"    Capture saved: {pcap_file} ({pcap_file.stat().st_size // 1024}KB)")

        # Convert PKTAP to standard pcap for tshark
        converted = pcap_file.parent / "iphone_traffic_converted.pcap"
        print("    Converting pcap format for tshark...")
        subprocess.run([
            "sudo", "tcpdump",
            "-r", str(pcap_file),
            "-s", "65535",
            "-w", str(converted),
        ], capture_output=True, text=True)

        if converted.exists() and converted.stat().st_size > 100:
            pcap_file.unlink()
            converted.rename(pcap_file)
            print(f"    Traffic ready: {pcap_file}")
        else:
            print("    Note: Using original PKTAP pcap")
        return pcap_file
    else:
        print("    NOTE: No traffic captured — pcap is empty.")
        return None


# ══════════════════════════════════════════════════════
#  AUTO IOC LOADING — MANIFEST-DRIVEN CTI INGESTION
# ══════════════════════════════════════════════════════
#
# Rather than pinning individual feed URLs (which break whenever the
# upstream repository is reorganised), read the authoritative manifest
# published by the MVT project and follow whatever it lists. The corpus
# then updates itself as new campaigns are published.

MANIFEST_URL = ("https://raw.githubusercontent.com/"
                "mvt-project/mvt-indicators/main/indicators.yaml")

# Feeds excluded as Android-only. Their indicators cannot match on iOS:
# APK hashes, package identifiers and signing certificates have no
# iOS equivalent. Excluded by name, and the exclusion is reported.
EXCLUDED_FEEDS = {
    "Stalkerware Indicators of Compromise",
    "Surveillance campaign linked to mercenary spyware company",
}

# STIX object types that cannot match on iOS. Counted, then discarded.
ANDROID_ONLY_TYPES = ("app:id", "app:cert.sha1", "app:cert.sha256",
                      "android-property:name")

# Used only if the manifest itself is unreachable.
FALLBACK_FEEDS = [
    {"name": "DarkSword", "owner": "mvt-project", "repo": "mvt-indicators",
     "branch": "main", "path": "2026-03-30_darksword/darksword.stix2"},
    {"name": "Coruna", "owner": "mvt-project", "repo": "mvt-indicators",
     "branch": "main", "path": "2026-03-03_coruna_cryptowaters/coruna.stix2"},
    {"name": "NSO Group Pegasus", "owner": "AmnestyTech", "repo": "investigations",
     "branch": "master", "path": "2021-07-18_nso/pegasus.stix2"},
    {"name": "Predator Spyware", "owner": "mvt-project", "repo": "mvt-indicators",
     "branch": "main", "path": "intellexa_predator/predator.stix2"},
    {"name": "Quadream KingSpawn", "owner": "mvt-project", "repo": "mvt-indicators",
     "branch": "main", "path": "2023-04-11_quadream/kingspawn.stix2"},
    {"name": "Operation Triangulation", "owner": "mvt-project", "repo": "mvt-indicators",
     "branch": "main",
     "path": "2023-06_01_operation_triangulation/operation_triangulation.stix2"},
]


def empty_iocs():
    """The nine indicator classes the scanner understands."""
    return {
        "domains":     [],
        "ips":         [],
        "file_paths":  [],
        "file_names":  [],
        "hashes":      [],
        "urls":        [],
        "processes":   [],
        "emails":      [],
        "profile_ids": [],
    }


def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "ioc-scanner/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_manifest(text):
    """
    Minimal parser for the fixed shape of indicators.yaml.
    Avoids a PyYAML dependency so the tool remains standard-library only.
    """
    feeds, cur = [], None
    for raw in text.splitlines():
        st = raw.strip()
        if st.startswith("name:") and "meta" not in st:
            if cur and cur.get("path"):
                feeds.append(cur)
            cur = {"name": st.split("name:", 1)[1].strip()}
        elif cur is not None:
            for k in ("owner", "repo", "branch", "path"):
                if st.startswith(k + ":"):
                    cur[k] = st.split(":", 1)[1].strip()
    if cur and cur.get("path"):
        feeds.append(cur)
    return [f for f in feeds
            if all(k in f for k in ("owner", "repo", "branch", "path"))]


def parse_stix2(data):
    """
    Extract indicators from a STIX 2.1 bundle.

    Handles both spellings of the SHA256 key: MVT emits
    file:hashes.sha256 while OTX-derived bundles emit
    file:hashes.'SHA-256'. Matching only the first silently
    discards the second.
    """
    iocs = empty_iocs()
    skipped = 0

    try:
        bundle = json.loads(data)
    except Exception:
        return iocs, 0

    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue

        m = re.match(r"\[\s*([A-Za-z0-9_\-\.':]+)\s*=\s*'([^']*)'",
                     obj.get("pattern", ""))
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if not val:
            continue

        if key in ANDROID_ONLY_TYPES:
            skipped += 1
            continue

        norm = key.lower().replace("'", "").replace("-", "")

        if   key == "domain-name:value":        bucket = "domains"
        elif key == "ipv4-addr:value":          bucket = "ips"
        elif key == "file:path":                bucket = "file_paths"
        elif key == "file:name":                bucket = "file_names"
        elif norm == "file:hashes.sha256":      bucket = "hashes"; val = val.lower()
        elif key == "url:value":                bucket = "urls"
        elif key == "process:name":             bucket = "processes"
        elif key == "email-addr:value":         bucket = "emails"
        elif key == "configuration-profile:id": bucket = "profile_ids"
        else:
            continue

        if val not in iocs[bucket]:
            iocs[bucket].append(val)

    return iocs, skipped


def merge_iocs(base, new):
    for k in base:
        for item in new.get(k, []):
            if item not in base[k]:
                base[k].append(item)
    return base


def fetch_live_iocs():
    """Read the MVT manifest, then retrieve every feed it lists."""
    print("\n[AUTO] Fetching live IOCs from threat intelligence feeds...")
    print("    Reading MVT indicator manifest...")

    try:
        feeds = parse_manifest(http_get(MANIFEST_URL))
        print(f"    Manifest lists {len(feeds)} indicator collections.")
    except Exception as e:
        print(f"    Manifest unreachable ({type(e).__name__}); using fallback list.")
        feeds = FALLBACK_FEEDS

    kept = [f for f in feeds if f["name"] not in EXCLUDED_FEEDS]
    dropped = len(feeds) - len(kept)
    if dropped:
        print(f"    Excluding {dropped} Android-only collection(s).")
    print()

    combined = empty_iocs()
    ok = failed = android_skipped = 0

    for f in kept:
        url = (f"https://raw.githubusercontent.com/"
               f"{f['owner']}/{f['repo']}/{f['branch']}/{f['path']}")
        label = f["name"].replace(" Indicators of Compromise", "")[:42]
        try:
            parsed, skipped = parse_stix2(http_get(url))
            android_skipped += skipped
            n = sum(len(v) for v in parsed.values())
            combined = merge_iocs(combined, parsed)
            ok += 1
            print(f"    [ok]   {label:<44} {n:>6} IOCs")
        except Exception as e:
            failed += 1
            print(f"    [SKIP] {label:<44} {type(e).__name__}")

    total = sum(len(v) for v in combined.values())
    print(f"\n    Feeds retrieved : {ok} of {ok + failed}")
    print(f"    Unique IOCs     : {total}")
    print(f"      Domains          : {len(combined['domains'])}")
    print(f"      IP addresses     : {len(combined['ips'])}")
    print(f"      File paths       : {len(combined['file_paths'])}")
    print(f"      File names       : {len(combined['file_names'])}")
    print(f"      SHA256 hashes    : {len(combined['hashes'])}")
    print(f"      URLs             : {len(combined['urls'])}")
    print(f"      Process names    : {len(combined['processes'])}")
    print(f"      Email addresses  : {len(combined['emails'])}")
    print(f"      Config profiles  : {len(combined['profile_ids'])}")
    if android_skipped:
        print(f"      (skipped {android_skipped} Android-only indicators)")

    return combined


# ══════════════════════════════════════════════════════
#  STEP 5 — GET IOCs FROM USER
# ══════════════════════════════════════════════════════

def get_iocs():
    print("\n[5] Paste your IOCs below.")
    print("    One per line. Type END when done.\n")

    iocs = empty_iocs()

    while True:
        line = input("    > ").strip()
        if line.upper() == "END":
            break
        if not line:
            continue

        if line.startswith("/private/var/"):
            iocs["file_paths"].append(line)
        elif line.endswith((".js", ".txt", ".db", ".kb", ".sqlite", ".plist")):
            iocs["file_names"].append(line)
        elif len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
            iocs["hashes"].append(line.lower())
        elif line[0].isdigit():
            iocs["ips"].append(line)
        else:
            iocs["domains"].append(line)

    total = sum(len(v) for v in iocs.values())
    print(f"\n    Got {total} IOCs:")
    print(f"      Domains:    {len(iocs['domains'])}")
    print(f"      IPs:        {len(iocs['ips'])}")
    print(f"      File paths: {len(iocs['file_paths'])}")
    print(f"      File names: {len(iocs['file_names'])}")
    print(f"      Hashes:     {len(iocs['hashes'])}")
    return iocs


# ══════════════════════════════════════════════════════
#  STEP 6 — READ BACKUP MANIFEST
# ══════════════════════════════════════════════════════

def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None


def read_backup(backup_path):
    print("\n[6] Reading backup manifest...")

    manifest = backup_path / "Manifest.db"
    if not manifest.exists():
        print("    ERROR: Manifest.db not found.")
        print("    Turn off encrypted backup in Finder and re-run.")
        exit()

    file_map = {}
    conn = sqlite3.connect(str(manifest))
    cur  = conn.cursor()
    cur.execute("SELECT fileID, relativePath FROM Files WHERE relativePath IS NOT NULL")

    for file_id, rel_path in cur.fetchall():
        full_path = f"/private/var/{rel_path}"
        file_map[full_path] = file_id
        file_map[rel_path]  = file_id

    conn.close()
    print(f"    Found {len(file_map) // 2} files in backup.")
    return file_map


# ══════════════════════════════════════════════════════
#  STEP 7A — SILENT DOMAIN LOAD ANALYSIS (INNOVATIVE)
# ══════════════════════════════════════════════════════

def scan_silent_domain_loads(backup_path, iocs):
    """
    Queries Safari ResourceLoadStatistics database specifically
    for domains loaded WITHOUT user interaction (hadUserInteraction = 0).

    This is more forensically significant than simple string matching
    because:
    - hadUserInteraction = 0 means the user NEVER consciously visited
    - Silent loads are consistent with exploit chain behaviour
    - Browser-based iOS exploits like DarkSword and Pegasus load
      their C2 domains as background WebKit resources
    - This provides HIGH CONFIDENCE matches vs string search

    No other free iOS forensic tool specifically queries this field.
    """
    print("\n    [INNOVATIVE] Scanning Safari silent domain loads...")
    hits = []

    # Find the ResourceLoadStatistics database in backup
    obs_db_path = None
    obs_db_file = "observations.db"

    for root, _, files in os.walk(backup_path):
        for fname in files:
            fpath = Path(root) / fname
            # Check if this blob is the ResourceLoadStatistics db
            try:
                # Try opening as SQLite to check if it has ObservedDomains table
                conn_test = sqlite3.connect(str(fpath))
                cur_test  = conn_test.cursor()
                cur_test.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='ObservedDomains';"
                )
                result = cur_test.fetchone()
                conn_test.close()
                if result:
                    obs_db_path = fpath
                    break
            except:
                continue
        if obs_db_path:
            break

    if not obs_db_path:
        print("    NOTE: ResourceLoadStatistics database not found in backup.")
        return hits

    print(f"    Found ResourceLoadStatistics database.")

    try:
        conn = sqlite3.connect(str(obs_db_path))
        cur  = conn.cursor()

        # Get ALL domains loaded WITHOUT user interaction
        cur.execute("""
            SELECT registrableDomain, lastSeen, isPrevalent, isVeryPrevalent
            FROM ObservedDomains
            WHERE hadUserInteraction = 0
            AND registrableDomain IS NOT NULL
            ORDER BY lastSeen DESC
        """)

        silent_domains = cur.fetchall()
        conn.close()

        print(f"    Found {len(silent_domains)} domains loaded silently (hadUserInteraction=0)")

        # Save full silent domain list for reference
        silent_log = Path.home() / "iphone_scan" / "silent_domains.txt"
        with open(silent_log, "w") as f:
            f.write("Domains loaded silently on your iPhone (hadUserInteraction=0)\n")
            f.write("These domains were loaded without your conscious knowledge\n")
            f.write("=" * 60 + "\n\n")
            for domain, last_seen, prevalent, very_prevalent in silent_domains:
                f.write(f"{domain}\n")
        print(f"    Full silent domain list saved to: {silent_log}")

        # Cross reference against IOC domains
        already_found = set()
        for domain, last_seen, prevalent, very_prevalent in silent_domains:
            for ioc in iocs["domains"]:
                if (domain == ioc or domain.endswith("." + ioc)) and ioc not in already_found:
                    already_found.add(ioc)
                    hits.append(
                        f"[SILENT LOAD - HIGH CONFIDENCE]\n"
                        f"   Domain:              {domain}\n"
                        f"   Matched IOC:         {ioc}\n"
                        f"   hadUserInteraction:  0 (never consciously visited)\n"
                        f"   isPrevalent:         {bool(prevalent)}\n"
                        f"   Significance:        Domain was loaded silently in the background\n"
                        f"                        Consistent with exploit chain C2 communication"
                    )

        if not hits:
            print("    No IOC domains found in silent loads — CLEAN")
        else:
            print(f"    ALERT: {len(hits)} IOC domain(s) found in silent loads")

    except Exception as e:
        print(f"    ERROR reading ResourceLoadStatistics: {e}")

    return hits


# ══════════════════════════════════════════════════════
#  STEP 7 — SCAN BACKUP
# ══════════════════════════════════════════════════════

def scan_backup(backup_path, file_map, iocs):
    print("\n    Scanning backup files...")
    hits = []

    # ── File paths — EXACT match only ─────────────────────────────────
    # The full iOS path must match exactly.
    # e.g. IOC /private/var/tmp/keychain_dump.txt must be found
    # at exactly that path — not just anywhere with that filename.
    for path in iocs["file_paths"]:
        matched = False
        for mapped in file_map:
            if mapped == path:   # exact full path match only
                hits.append(
                    f"[BACKUP - FILE PATH]   {path}\n"
                    f"                       Found at exact path: {mapped}"
                )
                matched = True
                break
        if not matched:
            print(f"    [FILE PATH] NOT FOUND: {path}")
            print(f"       Note: This path requires system-level access.")
            print(f"       On non-jailbroken iPhone, files cannot be written")
            print(f"       to /private/var/tmp/ — only app sandboxes are accessible.")

    # ── File names — filename match only ──────────────────────────────
    # Only the filename is checked — not the full path.
    # A match means a file with this exact name exists somewhere on the phone.
    # The path where it was found is reported for context.
    for name in iocs["file_names"]:
        for mapped in file_map:
            if Path(mapped).name == name:
                hits.append(
                    f"[BACKUP - FILE NAME]   {name}\n"
                    f"                       Found at: {mapped}"
                )
                break

    # Hashes
    seen = set()
    for ios_path, file_id in file_map.items():
        if file_id in seen:
            continue
        seen.add(file_id)
        blob = backup_path / file_id[:2] / file_id
        if not blob.exists():
            continue
        digest = sha256(blob)
        if digest and digest.lower() in iocs["hashes"]:
            hits.append(f"[BACKUP - HASH]        {digest}  at  {ios_path}")

    # Domains and IPs in backup files
    all_network   = (iocs["domains"] + iocs["ips"] + iocs["urls"]
                     + iocs["emails"] + iocs["profile_ids"])
    already_found = set()
    if all_network:
        print("    Searching backup for domains, IPs, URLs and profile IDs...")
        for root, _, files in os.walk(backup_path):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    content = fpath.read_bytes().decode("utf-8", errors="ignore")
                    for ioc in all_network:
                        if ioc in content and ioc not in already_found:
                            already_found.add(ioc)
                            hits.append(f"[BACKUP - NETWORK]     {ioc}  in file  {fpath.name}")
                except:
                    continue

    return hits


# ══════════════════════════════════════════════════════
#  STEP 8 — SCAN SYSDIAGNOSE LOGS
# ══════════════════════════════════════════════════════

def scan_sysdiagnose(sysdiag_folder, iocs):
    if not sysdiag_folder:
        return []

    print("\n    Scanning sysdiagnose logs...")
    hits          = []
    # Process names are matched here specifically: crash reports name the
    # process that faulted, which is how Operation Triangulation was found.
    all_iocs = (iocs["domains"] + iocs["ips"] + iocs["file_names"]
                + iocs["file_paths"] + iocs["processes"]
                + iocs["urls"] + iocs["emails"])
    already_found = set()

    for fpath in sysdiag_folder.rglob("*"):
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_bytes().decode("utf-8", errors="ignore")
            for ioc in all_iocs:
                key = (ioc, fpath.name)
                if ioc in content and key not in already_found:
                    already_found.add(key)
                    hits.append(f"[SYSDIAGNOSE]          {ioc}  in  {fpath.name}")
        except:
            continue

    return hits


# ══════════════════════════════════════════════════════
#  STEP 9 — SCAN NETWORK TRAFFIC
# ══════════════════════════════════════════════════════

def extract_dns_queries(pcap_file):
    if not shutil.which("tshark"):
        return None, "tshark not found"

    print("    Extracting DNS queries with tshark...")

    def run_tshark(path):
        r = subprocess.run([
            "tshark", "-r", str(path),
            "-Y", "dns.flags.response == 0",
            "-T", "fields",
            "-e", "dns.qry.name",
            "-E", "separator=,",
        ], capture_output=True, text=True)
        if not r.stdout.strip():
            r = subprocess.run([
                "tshark", "-r", str(path),
                "-T", "fields",
                "-e", "dns.qry.name",
                "-E", "separator=,",
            ], capture_output=True, text=True)
        return r

    result = run_tshark(pcap_file)

    if not result.stdout.strip():
        desktop_pcap = Path.home() / "Desktop" / "iphone_capture_converted.pcap"
        if desktop_pcap.exists() and desktop_pcap.stat().st_size > 100:
            print("    Using previously captured traffic file...")
            result = run_tshark(desktop_pcap)

    if not result.stdout.strip():
        return None, "No DNS queries found in capture"

    domains = set()
    for line in result.stdout.strip().splitlines():
        for part in line.split(","):
            d = part.strip().lower().rstrip(".")
            if d:
                domains.add(d)
    return domains, None


def extract_ip_connections(pcap_file):
    if not shutil.which("tshark"):
        return None

    result = subprocess.run([
        "tshark", "-r", str(pcap_file),
        "-T", "fields",
        "-e", "ip.dst",
        "-E", "separator=,",
    ], capture_output=True, text=True)

    ips = set()
    for line in result.stdout.splitlines():
        for part in line.split(","):
            ip = part.strip()
            if ip:
                ips.add(ip)
    return ips


def scan_traffic(pcap_file, iocs):
    if not pcap_file:
        return []

    print("\n    Scanning network traffic and DNS queries...")
    hits          = []
    already_found = set()

    if not shutil.which("tshark"):
        print("    tshark not found. Install with: brew install wireshark")
        return []

    # ── DNS queries ────────────────────────────────────
    resolved_domains, err = extract_dns_queries(pcap_file)

    if err:
        print(f"    NOTE: {err}")
    else:
        print(f"    Found {len(resolved_domains)} unique DNS queries from your phone.")

        # Save plain list
        dns_log = Path.home() / "iphone_scan" / "traffic" / "dns_queries.txt"
        dns_log.write_text("\n".join(sorted(resolved_domains)))

        # Save readable report
        dns_report     = Path.home() / "iphone_scan" / "traffic" / "dns_report.txt"
        ioc_domain_set = set(iocs["domains"])
        lines          = []
        lines.append("=" * 55)
        lines.append("  DNS QUERY REPORT")
        lines.append(f"  Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Total : {len(resolved_domains)} unique domains")
        lines.append("=" * 55)
        lines.append("")
        lines.append("  STATUS    DOMAIN")
        lines.append("  --------  " + "-" * 40)
        malicious_dns = []
        for domain in sorted(resolved_domains):
            flagged = any(
                domain == ioc or domain.endswith("." + ioc)
                for ioc in ioc_domain_set
            )
            if flagged:
                lines.append(f"  MALICIOUS {domain}")
                malicious_dns.append(domain)
            else:
                lines.append(f"  CLEAN     {domain}")
        lines.append("")
        lines.append(f"  Total: {len(resolved_domains)}  Clean: {len(resolved_domains)-len(malicious_dns)}  Malicious: {len(malicious_dns)}")
        lines.append("=" * 55)
        dns_report.write_text("\n".join(lines))
        print(f"    DNS list   saved to: {dns_log}")
        print(f"    DNS report saved to: {dns_report}")

        # Match IOC domains
        for ioc_domain in iocs["domains"]:
            for resolved in resolved_domains:
                if resolved == ioc_domain or resolved.endswith("." + ioc_domain):
                    if ioc_domain not in already_found:
                        already_found.add(ioc_domain)
                        hits.append(f"[DNS QUERY]            {ioc_domain}  —  phone resolved: {resolved}")

    # ── IP connections ─────────────────────────────────
    connected_ips = extract_ip_connections(pcap_file)
    if connected_ips:
        print(f"    Found {len(connected_ips)} unique destination IPs.")

        ip_log = Path.home() / "iphone_scan" / "traffic" / "ip_connections.txt"
        ip_log.write_text("\n".join(sorted(connected_ips)))

        ip_report  = Path.home() / "iphone_scan" / "traffic" / "ip_report.txt"
        ioc_ip_set = set(iocs["ips"])
        ip_lines   = []
        ip_lines.append("=" * 55)
        ip_lines.append("  IP CONNECTION REPORT")
        ip_lines.append(f"  Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        ip_lines.append(f"  Total : {len(connected_ips)} unique IPs")
        ip_lines.append("=" * 55)
        ip_lines.append("")
        ip_lines.append("  STATUS    IP ADDRESS")
        ip_lines.append("  --------  " + "-" * 20)
        malicious_ips = []
        for ip in sorted(connected_ips):
            if ip in ioc_ip_set:
                ip_lines.append(f"  MALICIOUS {ip}")
                malicious_ips.append(ip)
            else:
                ip_lines.append(f"  CLEAN     {ip}")
        ip_lines.append("")
        ip_lines.append(f"  Total: {len(connected_ips)}  Malicious: {len(malicious_ips)}")
        ip_lines.append("=" * 55)
        ip_report.write_text("\n".join(ip_lines))
        print(f"    IP list   saved to: {ip_log}")
        print(f"    IP report saved to: {ip_report}")

        for ioc_ip in iocs["ips"]:
            if ioc_ip in connected_ips and ioc_ip not in already_found:
                already_found.add(ioc_ip)
                hits.append(f"[IP CONNECTION]        {ioc_ip}  —  phone connected to this IP")

    return hits


# ══════════════════════════════════════════════════════
#  STEP 10 — SHOW AND SAVE RESULTS
# ══════════════════════════════════════════════════════

def show_results(all_hits):
    print("\n" + "=" * 55)
    print("  SCAN RESULTS")
    print("=" * 55)

    if not all_hits:
        print("\n  CLEAN — No IOC matches found across all sources.\n")
    else:
        print(f"\n  WARNING — {len(all_hits)} match(es) found:\n")
        for hit in all_hits:
            print(f"  !! {hit}")
        print("\n  Recommended: Contact Apple Support or run iVerify.")

    print("\n" + "=" * 55)

    report = Path.home() / "iphone_scan" / "ioc_scan_report.txt"
    report.parent.mkdir(parents=True, exist_ok=True)

    with open(report, "w") as f:
        f.write("iPhone IOC Scan Report\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 55 + "\n\n")
        if all_hits:
            f.write(f"RESULT: INFECTED — {len(all_hits)} IOC match(es) found\n\n")
            for hit in all_hits:
                f.write(f"{hit}\n")
        else:
            f.write("RESULT: CLEAN — No IOC matches found.\n")

    print(f"\n  Report saved to: {report}\n")
    print("  All scan data saved to: ~/iphone_scan/\n")


# ══════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════

AUTO_MODE = "--auto" in sys.argv

print("\n" + "=" * 55)
if AUTO_MODE:
    print("  iPhone IOC Scanner — AUTO MODE")
    print("  IOCs loaded automatically from live CTI feeds")
else:
    print("  iPhone IOC Scanner — MANUAL MODE")
    print("  Scanning real connected iPhone")
print("=" * 55)

udid          = get_udid()
backup_path   = backup_phone(udid)
sysdiag_path  = grab_sysdiagnose(udid)
pcap_file     = capture_traffic(udid)

if AUTO_MODE:
    iocs = fetch_live_iocs()
else:
    iocs = get_iocs()

file_map      = read_backup(backup_path)

print("\n[7] Scanning all sources...")
hits  = []
hits += scan_backup(backup_path, file_map, iocs)
hits += scan_sysdiagnose(sysdiag_path, iocs)
hits += scan_traffic(pcap_file, iocs)
hits += scan_silent_domain_loads(backup_path, iocs)

show_results(hits)
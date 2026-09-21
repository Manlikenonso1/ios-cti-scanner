#!/usr/bin/env python3
"""
iPhone IOC scanner: multi-source version
-----------------------------------------
What it does:
  1. Finds your iPhone (plug it in and tap Trust first)
  2. Takes a full backup into a new folder named with today's date
  3. Pulls crash reports and system logs off the phone
  4. Records 60 seconds of network traffic while you use the phone
  5. Downloads indicators from three places, one at a time:
       A. the MVT manifest (skipping the same Android-only sets as before)
       B. Echap's stalkerware list (network indicators only, since the
          rest of it only applies to Android)
       C. Citizen Lab's indicators (their CSV and JSON files)
  6. Counts how many indicators each source has and how much they overlap
  7. Checks the phone data against all of them and says which source
     each match came from

Run it:          python3 ioc_scanner_multisource.py
Try it first:    python3 ioc_scanner_multisource.py --sources-only
                 (downloads and compares the sources; no phone needed)

Everything is saved to ~/iphone_scan_multi_<date>/, so older scans are
never touched.
"""

import os, sys, time, sqlite3, hashlib, subprocess, shutil, re, json
import csv, io, zipfile, signal, urllib.request
from pathlib import Path
from datetime import datetime

STARTED = datetime.now()
BASE = Path.home() / f"iphone_scan_multi_{STARTED:%Y%m%d_%H%M}"
SOURCES_ONLY = "--sources-only" in sys.argv


# ------------------------------------------------------
#  STEP 1 - FIND THE PHONE
# ------------------------------------------------------

def get_udid():
    print("\n[1] Looking for your iPhone...")
    if not shutil.which("idevice_id"):
        sys.exit("    libimobiledevice isn't installed. Run: brew install libimobiledevice")
    udid = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True).stdout.strip()
    if not udid:
        sys.exit("    Can't see an iPhone. Plug it in and tap Trust on the phone.")
    print(f"    Phone found: {udid}")
    return udid


def get_ios_version(udid):
    if not shutil.which("ideviceinfo"):
        return "unknown"
    r = subprocess.run(["ideviceinfo", "-u", udid, "-k", "ProductVersion"],
                       capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


# ------------------------------------------------------
#  STEP 2 - BACK UP THE PHONE (full backup, fresh folder every run)
# ------------------------------------------------------

def backup_phone(udid):
    print("\n[2] Backing up iPhone (full backup)...")
    if not shutil.which("idevicebackup2"):
        sys.exit("    idevicebackup2 isn't installed. Run: brew install libimobiledevice")
    backup_folder = BASE / "backup"
    backup_folder.mkdir(parents=True, exist_ok=True)
    print(f"    Saving to: {backup_folder}\n    This can take a few minutes...\n")
    subprocess.run(["idevicebackup2", "-u", udid, "backup", "--full", str(backup_folder)])
    backup_path = backup_folder / udid
    if not (backup_path / "Manifest.db").exists():
        sys.exit("    The backup didn't finish. Check that encrypted backups are switched off in Finder.")
    print(f"    Backup complete: {backup_path}")
    return backup_path


# ------------------------------------------------------
#  STEP 3 - PULL CRASH REPORTS AND LOGS
# ------------------------------------------------------

def grab_sysdiagnose(udid):
    print("\n[3] Pulling crash reports and system logs...")
    if not shutil.which("idevicecrashreport"):
        print("    Skipping: idevicecrashreport isn't installed.")
        return None
    folder = BASE / "sysdiagnose"
    folder.mkdir(parents=True, exist_ok=True)
    subprocess.run(["idevicecrashreport", "-u", udid, "-e", "-k", str(folder)],
                   capture_output=True, text=True)
    files = [f for f in folder.rglob("*") if f.is_file()]
    if not files:
        print("    No logs on the phone at the moment.")
        return None
    print(f"    Got {len(files)} log files  ->  {folder}")
    return folder


# ------------------------------------------------------
#  STEP 4 - RECORD NETWORK TRAFFIC
# ------------------------------------------------------

def capture_traffic(udid, duration=60):
    print("\n[4] Recording network traffic (rvictl + tcpdump)...")
    if not shutil.which("rvictl"):
        print("    Skipping: rvictl isn't available. Install Xcode.")
        return None
    if not shutil.which("tcpdump"):
        print("    Skipping: tcpdump isn't available.")
        return None

    folder = BASE / "traffic"
    folder.mkdir(parents=True, exist_ok=True)
    pcap_file = folder / "iphone_traffic.pcap"

    subprocess.run(["rvictl", "-s", udid], capture_output=True)
    print("    Waiting for the rvi0 interface to come up...")
    time.sleep(5)
    if "rvi0" not in subprocess.run(["ifconfig", "rvi0"], capture_output=True, text=True).stdout:
        print("    rvi0 never came up, so no traffic was recorded.")
        subprocess.run(["rvictl", "-x", udid], capture_output=True)
        return None

    print(f"    Recording for {duration} seconds. Use the phone as normal now: open Safari and a few apps.\n")
    proc = subprocess.Popen(["sudo", "tcpdump", "-i", "rvi0", "-p", "-n",
                             "-s", "65535", "-w", str(pcap_file)])
    try:
        for remaining in range(duration, 0, -10):
            print(f"    {remaining} seconds left...")
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n    Stopped early.")
    finally:
        proc.send_signal(signal.SIGINT)
        proc.wait()
        time.sleep(2)
        subprocess.run(["rvictl", "-x", udid], capture_output=True)
        print("    rvi0 interface closed.")

    if not (pcap_file.exists() and pcap_file.stat().st_size > 100):
        print("    Nothing was recorded.")
        return None

    converted = folder / "iphone_traffic_converted.pcap"
    subprocess.run(["sudo", "tcpdump", "-r", str(pcap_file), "-s", "65535",
                    "-w", str(converted)], capture_output=True, text=True)
    if converted.exists() and converted.stat().st_size > 100:
        pcap_file.unlink()
        converted.rename(pcap_file)
    print(f"    Traffic saved: {pcap_file}")
    return pcap_file


# ------------------------------------------------------
#  READING INDICATORS (same logic as the original tool)
# ------------------------------------------------------

MANIFEST_URL = ("https://raw.githubusercontent.com/"
                "mvt-project/mvt-indicators/main/indicators.yaml")
ECHAP_URL = ("https://raw.githubusercontent.com/AssoEchap/"
             "stalkerware-indicators/master/generated/stalkerware.stix2")
CITIZENLAB_ZIP = ("https://codeload.github.com/citizenlab/"
                  "malware-indicators/zip/refs/heads/master")

# Same list as the August run, so the MVT results can be compared.
EXCLUDED_FEEDS = {
    "Stalkerware Indicators of Compromise",
    "Surveillance campaign linked to mercenary spyware company",
}
ANDROID_ONLY_TYPES = ("app:id", "app:cert.sha1", "app:cert.sha256",
                      "android-property:name")


def empty_iocs():
    return {"domains": [], "ips": [], "file_paths": [], "file_names": [],
            "hashes": [], "urls": [], "processes": [], "emails": [],
            "profile_ids": []}

CLASSES = list(empty_iocs().keys())


def http_get(url, timeout=60, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": "ioc-scanner/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if binary else data.decode("utf-8", errors="replace")


def parse_stix2(data):
    iocs, skipped = empty_iocs(), 0
    try:
        bundle = json.loads(data)
    except Exception:
        return iocs, 0
    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        m = re.match(r"\[\s*([A-Za-z0-9_\-\.':]+)\s*=\s*'([^']*)'", obj.get("pattern", ""))
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


def to_sets(iocs):
    return {k: set(v) for k, v in iocs.items()}


# ------------------------------------------------------
#  STEP 5A - SOURCE A: MVT MANIFEST
# ------------------------------------------------------

def fetch_mvt():
    print("\n[5A] MVT manifest")
    feeds, cur, in_sources = [], None, False
    for raw in http_get(MANIFEST_URL).splitlines():
        st = raw.strip()
        if st.startswith("name:") and "meta" not in st:
            if cur:
                feeds.append(cur)
            cur = {"name": st.split("name:", 1)[1].strip(), "publishers": []}
            in_sources = False
        elif cur is not None:
            if st.startswith("sources:"):
                in_sources = True
                continue
            if in_sources and st.startswith("- ") and not st.startswith("- http"):
                cur["publishers"].append(st[2:].strip())
                continue
            if st.endswith(":"):
                in_sources = False
            for k in ("owner", "repo", "branch", "path"):
                if st.startswith(k + ":"):
                    cur[k] = st.split(":", 1)[1].strip()
    if cur:
        feeds.append(cur)
    feeds = [f for f in feeds if all(k in f for k in ("owner", "repo", "branch", "path"))]

    combined, collections = to_sets(empty_iocs()), []
    for f in feeds:
        excluded = f["name"] in EXCLUDED_FEEDS
        url = f"https://raw.githubusercontent.com/{f['owner']}/{f['repo']}/{f['branch']}/{f['path']}"
        try:
            parsed, skipped = parse_stix2(http_get(url))
            n = sum(len(v) for v in parsed.values())
            status = "excluded" if excluded else "used"
            if not excluded:
                for k in CLASSES:
                    combined[k] |= set(parsed[k])
        except Exception as e:
            n, skipped, status = 0, 0, f"failed ({type(e).__name__})"
        collections.append({"name": f["name"], "publishers": f["publishers"],
                            "iocs": n, "android_skipped": skipped, "status": status})
        print(f"    {status:<9} {f['name'][:48]:<48} {n:>6}")
    print(f"    Total used: {sum(len(v) for v in combined.values())}")
    return combined, collections


# ------------------------------------------------------
#  STEP 5B - SOURCE B: ECHAP STALKERWARE LIST
# ------------------------------------------------------

def fetch_echap():
    print("\n[5B] Echap stalkerware list")
    parsed, skipped = parse_stix2(http_get(ECHAP_URL))
    # Only keep domains, IPs and URLs. Everything else in Echap's list is
    # Android-specific (app IDs, signing certificates, and hashes of APK
    # files), so it could never match anything on an iPhone.
    apk_hashes = len(parsed["hashes"])
    parsed = {k: (v if k in ("domains", "ips", "urls") else []) for k, v in parsed.items()}
    skipped += apk_hashes
    print(f"    {sum(len(v) for v in parsed.values())} network indicators kept, "
          f"{skipped} Android-only dropped (incl. {apk_hashes} APK hashes)")
    return to_sets(parsed), {"android_skipped": skipped, "apk_hashes_dropped": apk_hashes}


# ------------------------------------------------------
#  STEP 5C - SOURCE C: CITIZEN LAB
# ------------------------------------------------------

RE_IP   = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
RE_HASH = re.compile(r"^[0-9a-f]{64}$")
RE_DOM  = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$")
FILE_EXT = (".exe", ".dll", ".apk", ".zip", ".doc", ".docx", ".pdf", ".js", ".txt",
            ".db", ".plist", ".jpg", ".png", ".rtf", ".xls", ".scr")
MISP_MAP = {"domain": "domains", "hostname": "domains", "ip-dst": "ips",
            "ip-src": "ips", "sha256": "hashes", "url": "urls",
            "email-src": "emails", "email-dst": "emails", "filename": "file_names"}


def classify(value, out):
    v = value.strip().strip('"').replace("[.]", ".").replace("hxxp", "http").lower()
    if not v or " " in v:
        return
    if RE_HASH.match(v):
        out["hashes"].add(v)
    elif RE_IP.match(v):
        out["ips"].add(v)
    elif v.startswith(("http://", "https://")):
        out["urls"].add(v)
    elif "@" in v and RE_DOM.match(v.split("@")[-1]):
        out["emails"].add(v)
    elif RE_DOM.match(v) and not v.endswith(FILE_EXT):
        out["domains"].add(v)


def fetch_citizenlab():
    print("\n[5C] Citizen Lab indicators")
    z = zipfile.ZipFile(io.BytesIO(http_get(CITIZENLAB_ZIP, binary=True)))
    out, parsed_files, not_parsed = to_sets(empty_iocs()), 0, {}
    for name in z.namelist():
        if name.endswith("/"):
            continue
        base = name.rsplit("/", 1)[-1].lower()
        ext = base.rsplit(".", 1)[-1] if "." in base else "(none)"
        text = z.read(name).decode("utf-8", errors="ignore")
        if ext == "csv":
            parsed_files += 1
            rows = list(csv.reader(io.StringIO(text)))
            head = [h.strip().lower() for h in rows[0]] if rows else []
            if "type" in head and "value" in head:
                ti, vi = head.index("type"), head.index("value")
                for r in rows[1:]:
                    if len(r) > max(ti, vi):
                        cls = MISP_MAP.get(r[ti].strip().lower())
                        if cls:
                            out[cls].add(r[vi].strip().lower())
            else:
                for r in rows:
                    for cell in r:
                        classify(cell, out)
        elif ext == "json":
            parsed_files += 1
            try:
                j = json.loads(text)
            except Exception:
                continue
            if isinstance(j, dict) and "objects" in j:
                p, _ = parse_stix2(text)
                for k in CLASSES:
                    out[k] |= set(p[k])
            elif isinstance(j, dict):
                ev = j.get("Event", j)
                for a in ev.get("Attribute", []) if isinstance(ev, dict) else []:
                    cls = MISP_MAP.get(str(a.get("type", "")).lower())
                    if cls:
                        out[cls].add(str(a.get("value", "")).strip().lower())
        else:
            not_parsed[ext] = not_parsed.get(ext, 0) + 1
    print(f"    Read {parsed_files} CSV/JSON files. Skipped other formats: {not_parsed}")
    print(f"    {sum(len(v) for v in out.values())} indicators")
    return out, {"files_parsed": parsed_files, "formats_not_parsed": not_parsed}


# ------------------------------------------------------
#  STEP 6 - HOW MUCH DO THE SOURCES OVERLAP?
# ------------------------------------------------------

def overlap(sources):
    names, res = list(sources), {}
    for cls in ("domains", "ips", "hashes", "ALL"):
        sets = {n: (set().union(*sources[n].values()) if cls == "ALL" else sources[n][cls])
                for n in names}
        row = {"sizes": {n: len(sets[n]) for n in names}, "shared": {}, "only_here": {}}
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                row["shared"][f"{a} & {b}"] = len(sets[a] & sets[b])
            others = set().union(*[sets[o] for o in names if o != a])
            row["only_here"][a] = len(sets[a] - others)
        res[cls] = row
    return res


# ------------------------------------------------------
#  STEP 7 - READ THE BACKUP AND LOOK FOR MATCHES (same checks as the original tool)
# ------------------------------------------------------

def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def read_backup(backup_path):
    print("\n[7] Reading the backup index (Manifest.db)...")
    file_map = {}
    conn = sqlite3.connect(str(backup_path / "Manifest.db"))
    for file_id, rel_path in conn.execute(
            "SELECT fileID, relativePath FROM Files WHERE relativePath IS NOT NULL"):
        file_map[f"/private/var/{rel_path}"] = file_id
        file_map[rel_path] = file_id
    conn.close()
    print(f"    {len(file_map) // 2} files in the backup.")
    return file_map


def scan_backup(backup_path, file_map, iocs):
    print("\n    Checking backup files...")
    hits = []

    for path in iocs["file_paths"]:
        if path in file_map:
            hits.append(f"[BACKUP - FILE PATH]   {path}\n"
                        f"                       Found at exact path: {path}")

    for name in iocs["file_names"]:
        for mapped in file_map:
            if Path(mapped).name == name:
                hits.append(f"[BACKUP - FILE NAME]   {name}\n"
                            f"                       Found at: {mapped}")
                break

    hash_set, seen = set(iocs["hashes"]), set()
    for ios_path, file_id in file_map.items():
        if file_id in seen:
            continue
        seen.add(file_id)
        blob = backup_path / file_id[:2] / file_id
        if blob.exists():
            digest = sha256(blob)
            if digest and digest.lower() in hash_set:
                hits.append(f"[BACKUP - HASH]        {digest}  at  {ios_path}")

    network = (iocs["domains"] + iocs["ips"] + iocs["urls"]
               + iocs["emails"] + iocs["profile_ids"])
    found = set()
    if network:
        print(f"    Searching backup for {len(network)} network indicators "
              "(this is the slowest step)...")
        for root, _, files in os.walk(backup_path):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    content = fpath.read_bytes().decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for ioc in network:
                    if ioc not in found and ioc in content:
                        found.add(ioc)
                        hits.append(f"[BACKUP - NETWORK]     {ioc}  in file  {fpath.name}")
    return hits


def scan_sysdiagnose(folder, iocs):
    if not folder:
        return []
    print("\n    Checking logs...")
    hits, found = [], set()
    all_iocs = (iocs["domains"] + iocs["ips"] + iocs["file_names"] + iocs["file_paths"]
                + iocs["processes"] + iocs["urls"] + iocs["emails"])
    for fpath in folder.rglob("*"):
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_bytes().decode("utf-8", errors="ignore")
        except Exception:
            continue
        for ioc in all_iocs:
            if (ioc, fpath.name) not in found and ioc in content:
                found.add((ioc, fpath.name))
                hits.append(f"[SYSDIAGNOSE]          {ioc}  in  {fpath.name}")
    return hits


def tshark_fields(pcap, field, dns_only=False):
    cmd = ["tshark", "-r", str(pcap), "-T", "fields", "-e", field, "-E", "separator=,"]
    if dns_only:
        cmd[3:3] = ["-Y", "dns.flags.response == 0"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    vals = set()
    for line in out.splitlines():
        for part in line.split(","):
            p = part.strip().lower().rstrip(".")
            if p:
                vals.add(p)
    return vals


def scan_traffic(pcap, iocs):
    if not pcap:
        return []
    if not shutil.which("tshark"):
        print("    tshark isn't installed. Run: brew install wireshark")
        return []
    print("\n    Checking network traffic...")
    hits = []
    folder = BASE / "traffic"

    dns = tshark_fields(pcap, "dns.qry.name", dns_only=True)
    (folder / "dns_queries.txt").write_text("\n".join(sorted(dns)))
    print(f"    {len(dns)} unique DNS queries (saved to dns_queries.txt)")
    for ioc in iocs["domains"]:
        for d in dns:
            if d == ioc or d.endswith("." + ioc):
                hits.append(f"[DNS QUERY]            {ioc}  —  phone resolved: {d}")
                break

    ips = tshark_fields(pcap, "ip.dst")
    (folder / "ip_connections.txt").write_text("\n".join(sorted(ips)))
    print(f"    {len(ips)} unique destination IPs (saved to ip_connections.txt)")
    for ioc in set(iocs["ips"]) & ips:
        hits.append(f"[IP CONNECTION]        {ioc}  —  phone connected to this IP")
    return hits


def scan_silent_domain_loads(backup_path, iocs):
    """Find domains Safari loaded without you tapping or typing anything
    (hadUserInteraction = 0 in ResourceLoadStatistics)."""
    print("\n    Checking Safari for silently loaded domains...")
    hits, obs_db = [], None
    for root, _, files in os.walk(backup_path):
        for fname in files:
            fpath = Path(root) / fname
            try:
                c = sqlite3.connect(f"file:{fpath}?mode=ro", uri=True)
                ok = c.execute("SELECT name FROM sqlite_master WHERE type='table' "
                               "AND name='ObservedDomains'").fetchone()
                c.close()
                if ok:
                    obs_db = fpath
                    break
            except Exception:
                continue
        if obs_db:
            break
    if not obs_db:
        print("    Couldn't find Safari's ResourceLoadStatistics database in the backup.")
        return hits

    c = sqlite3.connect(f"file:{obs_db}?mode=ro", uri=True)
    rows = c.execute("SELECT registrableDomain, lastSeen, isPrevalent FROM ObservedDomains "
                     "WHERE hadUserInteraction = 0 AND registrableDomain IS NOT NULL "
                     "ORDER BY lastSeen DESC").fetchall()
    c.close()
    (BASE / "silent_domains.txt").write_text("\n".join(r[0] for r in rows))
    print(f"    {len(rows)} domains loaded silently (saved to silent_domains.txt)")

    found = set()
    for domain, last_seen, prevalent in rows:
        for ioc in iocs["domains"]:
            if ioc not in found and (domain == ioc or domain.endswith("." + ioc)):
                found.add(ioc)
                hits.append(f"[SILENT LOAD - HIGH CONFIDENCE]\n"
                            f"   Domain:              {domain}\n"
                            f"   Matched IOC:         {ioc}\n"
                            f"   hadUserInteraction:  0 (never consciously visited)\n"
                            f"   isPrevalent:         {bool(prevalent)}")
    return hits


def attribute(hit, sources):
    m = re.search(r"Matched IOC:\s+(\S+)", hit) or re.match(r"\[[^\]]+\]\s+(\S+)", hit)
    ioc = m.group(1) if m else None
    return [n for n, s in sources.items() if ioc and any(ioc in v for v in s.values())]


# ------------------------------------------------------
#  STEP 8 - WRITE THE REPORT
# ------------------------------------------------------

def write_report(meta, sources, ov, mvt_cols, echap_meta, cl_meta, hits):
    names = list(sources)
    L = ["iPhone IOC Scan - multi-source run",
         f"Date:         {STARTED:%Y-%m-%d %H:%M:%S}",
         f"iOS version:  {meta['ios']}",
         f"Output folder: {BASE}", "=" * 64, "",
         "INDICATORS PER SOURCE (after Android-only filtering)",
         f"{'class':<14}" + "".join(f"{n:>12}" for n in names)]
    for k in CLASSES:
        L.append(f"{k:<14}" + "".join(f"{len(sources[n][k]):>12}" for n in names))
    L.append(f"{'TOTAL':<14}" + "".join(f"{sum(len(v) for v in sources[n].values()):>12}" for n in names))
    L += ["", "OVERLAP BETWEEN SOURCES"]
    for cls, row in ov.items():
        L += [f"  {cls}", f"    sizes:     {row['sizes']}",
              f"    shared:    {row['shared']}", f"    only here: {row['only_here']}"]
    L += ["", "MVT COLLECTIONS (status, indicators, publishers)"]
    for c in mvt_cols:
        L.append(f"  {c['status']:<9} {c['name'][:46]:<46} {c['iocs']:>6}  {', '.join(c['publishers'])}")
    L += ["", f"Echap:       {echap_meta}", f"Citizen Lab: {cl_meta}", ""]
    if SOURCES_ONLY:
        L.append("DEVICE MATCHES: skipped (--sources-only)")
    else:
        L.append(f"DEVICE MATCHES: {len(hits)}")
        for h in hits:
            L.append(f"  source(s): {', '.join(h['sources']) or 'unknown'}")
            L.append("    " + h["hit"].replace("\n", "\n    "))
        for n in names:
            L.append(f"  Matches from {n}: {sum(1 for h in hits if n in h['sources'])}")
    text = "\n".join(L)
    (BASE / "report.txt").write_text(text)
    (BASE / "results.json").write_text(json.dumps({
        "date": str(STARTED), **meta,
        "counts": {n: {k: len(v) for k, v in s.items()} for n, s in sources.items()},
        "overlap": ov, "mvt_collections": mvt_cols, "echap": echap_meta,
        "citizenlab": cl_meta, "hits": hits}, indent=2))
    return text


# ------------------------------------------------------
#  RUN
# ------------------------------------------------------

def main():
    BASE.mkdir(parents=True, exist_ok=True)
    print("\n" + "=" * 64)
    print("  iPhone IOC Scanner — MULTI-SOURCE RUN" + ("  (sources only)" if SOURCES_ONLY else ""))
    print(f"  Output: {BASE}")
    print("=" * 64)

    meta = {"ios": "not read", "udid": None}
    if not SOURCES_ONLY:
        udid = get_udid()
        meta = {"ios": get_ios_version(udid), "udid": udid}
        backup_path = backup_phone(udid)
        logs = grab_sysdiagnose(udid)
        pcap = capture_traffic(udid)

    mvt, mvt_cols = fetch_mvt()
    echap, echap_meta = fetch_echap()
    cl, cl_meta = fetch_citizenlab()
    sources = {"MVT": mvt, "Echap": echap, "CitizenLab": cl}
    ov = overlap(sources)

    hits = []
    if not SOURCES_ONLY:
        union = {k: sorted(set().union(*[s[k] for s in sources.values()])) for k in CLASSES}
        file_map = read_backup(backup_path)
        raw = []
        raw += scan_backup(backup_path, file_map, union)
        raw += scan_sysdiagnose(logs, union)
        raw += scan_traffic(pcap, union)
        raw += scan_silent_domain_loads(backup_path, union)
        hits = [{"hit": h, "sources": attribute(h, sources)} for h in raw]

    report = write_report(meta, sources, ov, mvt_cols, echap_meta, cl_meta, hits)
    print("\n" + report)
    print(f"\nSaved: {BASE / 'report.txt'} and {BASE / 'results.json'}\n")


if __name__ == "__main__":
    main()
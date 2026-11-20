#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EPSTEIN PUBLIC RECORDS ARCHIVER
Version: 0.2

Python 3.9+
Core: Python standard library only.

OPTIONAL:
    smartctl       - SMART health
    pdftotext      - PDF text extraction
    pdfinfo        - PDF page count
    pdftoppm       - PDF page rendering
    tesseract      - OCR
    whisper        - audio/video transcription
    Argos Translate - offline translation

The program:
    - inventories sources and URLs
    - discovers files
    - probes remote endpoints
    - calculates storage estimates
    - downloads files with resume support
    - hashes and verifies files
    - deduplicates identical downloads
    - inventories ZIP and TAR archives
    - performs optional OCR
    - performs optional translation
    - performs optional transcription
    - keeps logs and manifests
    - supports repeated update cycles

No fixed maximum download size.
One download at a time.
No automatic filesystem repair.
"""

import os
import sys
import re
import io
import json
import csv
import time
import html
import shutil
import hashlib
import sqlite3
import argparse
import platform
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import urllib.robotparser
import zipfile
import tarfile
import tempfile
import mimetypes
import email.message

from pathlib import Path
from datetime import datetime, timezone
from html.parser import HTMLParser


# ============================================================
# SETTINGS
# ============================================================

APP_NAME = "EPSTEIN PUBLIC RECORDS ARCHIVER"
VERSION = "0.2"

BLOCK_SIZE = 1024 * 1024
HTTP_TIMEOUT = 60

DEFAULT_RETRIES = 4
DEFAULT_DELAY = 0.8
DEFAULT_CRAWL_DEPTH = 2
DEFAULT_PAGE_LIMIT = 1500

MAX_HTML_SIZE = 5 * 1024 * 1024

USER_AGENT = "PublicRecordsArchive/0.2"

CRITICAL_HTTP_CODES = {
    401, 403, 404, 410, 429,
    500, 502, 503, 504
}

SUPPORTED_EXTENSIONS = {
    ".pdf", ".zip", ".7z", ".rar",
    ".tar", ".gz", ".tgz", ".bz2",
    ".csv", ".tsv", ".json", ".jsonl",
    ".xml", ".txt", ".rtf",
    ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".odt", ".ods",

    ".mp3", ".wav", ".m4a", ".aac",
    ".mp4", ".mov", ".avi", ".webm",
    ".mkv", ".mpeg", ".mpg",

    ".jpg", ".jpeg", ".png", ".gif",
    ".tif", ".tiff", ".webp", ".bmp"
}

MEDIA_EXTENSIONS = {
    ".mp3", ".wav", ".m4a", ".aac",
    ".mp4", ".mov", ".avi", ".webm",
    ".mkv", ".mpeg", ".mpg",
    ".jpg", ".jpeg", ".png", ".gif",
    ".tif", ".tiff", ".webp", ".bmp"
}

DATA_DIRECTORIES = (
    "01_RAW_OFFICIAL",
    "02_MEDIA_ARCHIVES",
    "03_SECONDARY_ARCHIVES",
    "04_COMMUNITY_RESEARCH",
    "05_DERIVED"
)

IGNORE_SCAN_DIRECTORIES = {
    "06_DATABASE",
    "07_MANIFESTS",
    "08_MONITORING",
    "09_LOGS",
    "99_STAGING"
}

DEFAULT_SETTINGS = {
    "delay": DEFAULT_DELAY,
    "retries": DEFAULT_RETRIES,
    "crawl_depth": DEFAULT_CRAWL_DEPTH,
    "page_limit": DEFAULT_PAGE_LIMIT,
    "include_media": False,
    "respect_robots": True,
    "verify_every_run": True,
    "user_agent": USER_AGENT,
    "internet_archive_query": 'title:(Epstein) AND mediatype:(texts)',
    "internet_archive_rows": 300,
    "ocr_languages": "eng+rus",
    "translation_from": "en",
    "translation_to": "ru",
    "whisper_model": "small"
}


# ============================================================
# SOURCE REGISTRY
# ============================================================

# Tiers:
# OFFICIAL
# MIRROR
# SECONDARY
# COMMUNITY

# Adapters:
# html
# google_drive
# dropbox
# internet_archive

SOURCES = [

    # DOJ

    ("doj_library",
     "DOJ Epstein Library",
     "OFFICIAL",
     "https://www.justice.gov/epstein",
     "html"),

    ("doj_disclosures",
     "DOJ Disclosures",
     "OFFICIAL",
     "https://www.justice.gov/epstein/doj-disclosures",
     "html"),

    ("doj_oip",
     "DOJ OIP Available Documents",
     "OFFICIAL",
     "https://www.justice.gov/oip/available-documents-oip",
     "html"),

    ("doj_oig_epstein",
     "DOJ OIG Epstein Report",
     "OFFICIAL",
     "https://www.oversight.gov/reports/investigation-and-review-federal-bureau-prisons-custody-care-and-supervision-jeffrey",
     "html"),

    ("doj_oig",
     "DOJ Inspector General",
     "OFFICIAL",
     "https://oig.justice.gov/reports",
     "html"),

    ("doj_opr",
     "DOJ Office of Professional Responsibility",
     "OFFICIAL",
     "https://www.justice.gov/archives/opa/pr/statement-doj-office-professional-responsibility-report-jeffrey-epstein-2006-2008",
     "html"),

    # FBI

    ("fbi_epstein",
     "FBI Vault Jeffrey Epstein",
     "OFFICIAL",
     "https://vault.fbi.gov/jeffrey-epstein/",
     "html"),

    ("fbi_review",
     "FBI Investigative Holdings Review",
     "OFFICIAL",
     "https://vault.fbi.gov/records-regarding-the-review-of-the-investigative-holdings-related-to-jeffrey-epstein/records-regarding-the-review-of-the-investigative-holdings-related-to-jeffrey-epstein",
     "html"),

    # CBP / BOP

    ("cbp_epstein",
     "CBP Epstein FOIA",
     "OFFICIAL",
     "https://www.cbp.gov/document/foia-record/jeffrey-epstein-records",
     "html"),

    ("bop_oig",
     "BOP / DOJ OIG",
     "OFFICIAL",
     "https://oig.justice.gov/",
     "html"),

    # HOUSE OVERSIGHT

    ("house_oversight",
     "House Oversight",
     "OFFICIAL",
     "https://oversight.house.gov/",
     "html"),

    ("house_doj_release",
     "House DOJ Production",
     "OFFICIAL",
     "https://oversight.house.gov/release/oversight-committee-releases-epstein-records-provided-by-the-department-of-justice/",
     "html"),

    ("house_estate_release",
     "House Estate Production",
     "OFFICIAL",
     "https://oversight.house.gov/release/oversight-committee-releases-additional-epstein-estate-documents/",
     "html"),

    ("house_doj_drive",
     "House DOJ Google Drive",
     "MIRROR",
     "https://drive.google.com/drive/folders/1TrGxDGQLDLZu1vvvZDBAh-e7wN3y6Hoz?usp=sharing",
     "google_drive"),

    ("house_doj_dropbox",
     "House DOJ Dropbox",
     "MIRROR",
     "https://www.dropbox.com/scl/fo/98fthv8otekjk28lcrnc5/AIn3egnE58MYe4Bn4fliVBw?dl=0&rlkey=m7p8e9omml96fgxl13kr2nuyt&st=0xvm0p08",
     "dropbox"),

    ("house_estate_drive",
     "House Estate Google Drive",
     "MIRROR",
     "https://drive.google.com/drive/folders/1hTNH5woIRio578onLGElkTWofUSWRoH_?usp=sharing",
     "google_drive"),

    ("house_estate_dropbox",
     "House Estate Dropbox",
     "MIRROR",
     "https://www.dropbox.com/scl/fo/9bq6uj0pnycpa4gxqiuzs/ABBA-BoYUAT7627MBeLiVYg?rlkey=3s6ggcjihou9nt8srsn2qt1n7&st=4aejaath&dl=0",
     "dropbox"),

    # SENATE

    ("senate_finance",
     "Senate Finance Committee",
     "OFFICIAL",
     "https://www.finance.senate.gov/ranking-members-news/wyden-releases-new-report-on-failure-of-wall-street-banks-to-blow-the-whistle-on-jeffrey-epsteins-sex-trafficking-and-money-laundering-schemes",
     "html"),

    # FLORIDA

    ("florida_sa15",
     "Florida State Attorney 15th Circuit",
     "OFFICIAL",
     "https://sa15.org/public-records/",
     "html"),

    # USVI

    ("usvi_recorder",
     "USVI Recorder of Deeds",
     "OFFICIAL",
     "https://usvi.publicsearch.us/",
     "html"),

    # COURTS

    ("pacer",
     "PACER",
     "OFFICIAL",
     "https://pacer.uscourts.gov/",
     "html"),

    ("courtlistener",
     "CourtListener RECAP",
     "MIRROR",
     "https://www.courtlistener.com/",
     "html"),

    # PRESIDENTIAL LIBRARIES

    ("bush_library",
     "George H. W. Bush Presidential Library",
     "OFFICIAL",
     "https://www.bush41library.gov/",
     "html"),

    # OTHER GOVERNMENT SOURCES

    ("govinfo",
     "GovInfo",
     "OFFICIAL",
     "https://www.govinfo.gov/",
     "html"),

    ("sec_edgar",
     "SEC EDGAR",
     "OFFICIAL",
     "https://www.sec.gov/edgar/search/",
     "html"),

    # FINANCIAL / CORPORATE

    ("propublica",
     "ProPublica Nonprofit Explorer",
     "SECONDARY",
     "https://projects.propublica.org/nonprofits/",
     "html"),

    ("opencorporates",
     "OpenCorporates",
     "SECONDARY",
     "https://opencorporates.com/",
     "html"),

    ("icij",
     "ICIJ Offshore Leaks",
     "SECONDARY",
     "https://offshoreleaks.icij.org/",
     "html"),

    # PUBLIC RECORDS

    ("muckrock",
     "MuckRock",
     "SECONDARY",
     "https://www.muckrock.com/",
     "html"),

    ("documentcloud",
     "DocumentCloud",
     "SECONDARY",
     "https://www.documentcloud.org/",
     "html"),

    ("internet_archive",
     "Internet Archive Epstein Search",
     "MIRROR",
     "https://archive.org/advancedsearch.php",
     "internet_archive"),

    # GOOGLE PINPOINT

    ("google_pinpoint",
     "Google Pinpoint Estate Collection",
     "SECONDARY",
     "https://journaliststudio.google.com/pinpoint/search?collection=092314e384a58618",
     "html"),

    # GITHUB INDEX

    ("github_index",
     "Epstein Files GitHub Index",
     "SECONDARY",
     "https://github.com/yung-megafone/Epstein-Files",
     "html"),

    # SEARCH / OCR INDEXES

    ("epsteinscan",
     "EpsteinScan",
     "SECONDARY",
     "https://www.epsteinscan.org/",
     "html"),

    ("epstein_exposed",
     "Epstein Exposed",
     "SECONDARY",
     "https://epsteinexposed.com/resources",
     "html"),

    ("epstein_project",
     "Epstein Project",
     "SECONDARY",
     "https://epsteinproject.org/",
     "html"),

    ("epstein_suite",
     "Epstein Suite",
     "SECONDARY",
     "https://epsteinsuite.com/",
     "html"),

    ("epstein_museum",
     "Epstein Museum",
     "SECONDARY",
     "https://epsteinmuseum.com/about.html",
     "html"),

    # JMAIL

    ("jmail_photos",
     "Jmail Photos",
     "SECONDARY",
     "https://jmail.world/photos",
     "html"),

    ("jmail_videos",
     "Jmail Videos",
     "SECONDARY",
     "https://jmail.world/jefftube",
     "html"),

    ("jmail_flights",
     "Jmail Flights",
     "SECONDARY",
     "https://jmail.world/flights",
     "html"),

    ("jmail_taxonomy",
     "Jmail Taxonomy",
     "SECONDARY",
     "https://jmail.world/taxonomy",
     "html"),

    ("jmail_about",
     "Jmail About",
     "SECONDARY",
     "https://jmail.world/about",
     "html"),

    ("jmail_wiki",
     "Jmail Wiki",
     "SECONDARY",
     "https://jmail.world/wiki",
     "html"),

    # OTHER RESEARCH TOOLS

    ("epstein_graph",
     "Epstein Graph",
     "SECONDARY",
     "https://epsteingraph.com/",
     "html"),

    ("money_network",
     "Money Network",
     "SECONDARY",
     "https://tommycarstensen.com/epstein/money_network.html",
     "html"),

    ("jeescholar",
     "JEEScholar",
     "SECONDARY",
     "https://jeescholar.com/",
     "html"),

    ("epstein_observer",
     "Epstein Observer",
     "SECONDARY",
     "https://epstein.observer/",
     "html"),

    ("track_the_files",
     "Track the Files",
     "SECONDARY",
     "https://trackthefiles.org/",
     "html"),

    ("epstein_unboxed",
     "Epstein Unboxed",
     "SECONDARY",
     "https://www.epsteinunboxed.com/",
     "html"),

    ("search_epstein_files",
     "Search Epstein Files",
     "SECONDARY",
     "https://searchepsteinfiles.com/",
     "html"),

    ("epstein_filez",
     "Epstein Filez",
     "SECONDARY",
     "https://epsteinfilez.com/",
     "html"),

    ("epstein_forums",
     "Epstein Forums",
     "SECONDARY",
     "https://epsteinforums.org/",
     "html"),

    # COMMUNITY

    ("reddit_megathread_1",
     "Reddit Research Megathread",
     "COMMUNITY",
     "https://www.reddit.com/r/Epstein/comments/1rc3gaz/megathread_list_of_research_tools_and_websites/",
     "html"),

    ("reddit_megathread_2",
     "Reddit Research Megathread Part 2",
     "COMMUNITY",
     "https://www.reddit.com/r/Epstein/comments/1wwsfs8/megathread_list_of_research_tools_and_websites/",
     "html"),
]


# ============================================================
# DIRECTORY STRUCTURE
# ============================================================

DIRECTORIES = [

    "00_ADMIN",

    "01_RAW_OFFICIAL/DOJ",
    "01_RAW_OFFICIAL/FBI",
    "01_RAW_OFFICIAL/CBP",
    "01_RAW_OFFICIAL/BOP",
    "01_RAW_OFFICIAL/HOUSE_OVERSIGHT/DOJ",
    "01_RAW_OFFICIAL/HOUSE_OVERSIGHT/ESTATE",
    "01_RAW_OFFICIAL/HOUSE_OVERSIGHT/TRANSCRIPTS",
    "01_RAW_OFFICIAL/SENATE_FINANCE",
    "01_RAW_OFFICIAL/DOJ_OIG",
    "01_RAW_OFFICIAL/DOJ_OPR",
    "01_RAW_OFFICIAL/FLORIDA",
    "01_RAW_OFFICIAL/US_VIRGIN_ISLANDS",
    "01_RAW_OFFICIAL/FEDERAL_COURTS",
    "01_RAW_OFFICIAL/PRESIDENTIAL_LIBRARIES",
    "01_RAW_OFFICIAL/SEC",
    "01_RAW_OFFICIAL/CORPORATE_REGISTRIES",
    "01_RAW_OFFICIAL/FOIA_EXTERNAL",

    "02_MEDIA_ARCHIVES/JMAIL/PHOTOS",
    "02_MEDIA_ARCHIVES/JMAIL/VIDEOS",
    "02_MEDIA_ARCHIVES/JMAIL/EMAILS",
    "02_MEDIA_ARCHIVES/JMAIL/FLIGHTS",
    "02_MEDIA_ARCHIVES/JMAIL/TAXONOMY",
    "02_MEDIA_ARCHIVES/OFFICIAL_AUDIO",
    "02_MEDIA_ARCHIVES/OFFICIAL_VIDEO",
    "02_MEDIA_ARCHIVES/OFFICIAL_PHOTOS",

    "03_SECONDARY_ARCHIVES/COURTLISTENER",
    "03_SECONDARY_ARCHIVES/GOOGLE_PINPOINT",
    "03_SECONDARY_ARCHIVES/INTERNET_ARCHIVE",
    "03_SECONDARY_ARCHIVES/EPSTEIN_PROJECT",
    "03_SECONDARY_ARCHIVES/EPSTEIN_EXPOSED",
    "03_SECONDARY_ARCHIVES/EPSTEINSCAN",
    "03_SECONDARY_ARCHIVES/OTHER_MIRRORS",

    "04_COMMUNITY_RESEARCH/FORUMS",
    "04_COMMUNITY_RESEARCH/TRANSCRIPTIONS",
    "04_COMMUNITY_RESEARCH/RESEARCH_REPORTS",
    "04_COMMUNITY_RESEARCH/FINANCIAL_ANALYSIS",
    "04_COMMUNITY_RESEARCH/NETWORK_GRAPHS",
    "04_COMMUNITY_RESEARCH/TIMELINES",

    "05_DERIVED/OCR",
    "05_DERIVED/EXTRACTED_TEXT",
    "05_DERIVED/TRANSLATIONS",
    "05_DERIVED/TRANSCRIPTS",
    "05_DERIVED/METADATA",
    "05_DERIVED/THUMBNAILS",

    "06_DATABASE",
    "07_MANIFESTS",
    "08_MONITORING",
    "09_LOGS",

    "99_STAGING/DISCOVERED",
    "99_STAGING/DOWNLOADING",
    "99_STAGING/QUARANTINE"
]


# ============================================================
# GENERAL HELPERS
# ============================================================

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def say(text=""):
    print(text, flush=True)


def pause():
    try:
        input("\nPress Enter...")
    except EOFError:
        pass


def human_size(value):

    if value is None:
        return "unknown"

    value = float(value)

    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024:
            return "%.2f %s" % (value, unit)

        value /= 1024

    return "%.2f PiB" % value


def safe_name(value):

    value = re.sub(
        r"[^A-Za-z0-9._() -]+",
        "_",
        str(value)
    )

    value = value.strip(" .")

    return value[:150] or "unknown"


def url_hash(url):

    return hashlib.sha256(
        url.encode("utf-8")
    ).hexdigest()


def file_sha256(path):

    digest = hashlib.sha256()

    with open(path, "rb") as source:

        while True:

            block = source.read(BLOCK_SIZE)

            if not block:
                break

            digest.update(block)

    return digest.hexdigest()


def normalize_url(url):

    if not url:
        return None

    url = urllib.parse.urldefrag(url)[0]

    parsed = urllib.parse.urlsplit(url)

    if parsed.scheme not in ("http", "https"):
        return None

    return url


def get_extension(path):

    return Path(
        urllib.parse.urlsplit(path).path
    ).suffix.lower()


def filename_from_url(url):

    parsed = urllib.parse.urlsplit(url)

    name = urllib.parse.unquote(
        parsed.path.rsplit("/", 1)[-1]
    )

    name = safe_name(name)

    if name == "unknown":
        name = "download"

    return name


def parse_content_disposition(value):

    if not value:
        return None

    message = email.message.Message()

    message["content-disposition"] = value

    name = message.get_filename()

    if name:
        return safe_name(name)

    match = re.search(
        r'filename="?([^";]+)',
        value,
        re.I
    )

    if match:
        return safe_name(match.group(1))

    return None


def write_json(path, data):

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as output:

        json.dump(
            data,
            output,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# INITIALIZATION
# ============================================================

def initialize(root):

    root.mkdir(parents=True, exist_ok=True)

    for item in DIRECTORIES:

        (root / item).mkdir(
            parents=True,
            exist_ok=True
        )

    readme = root / "00_ADMIN" / "README.txt"

    if not readme.exists():

        readme.write_text(
            APP_NAME + "\n\n"
            "Archive of publicly released records.\n"
            "Original files are stored separately from derived data.\n"
            "OCR, transcripts and translations are not originals.\n"
            "Preserve provenance and SHA-256 checksums.\n",
            encoding="utf-8"
        )

    policy = root / "00_ADMIN" / "COLLECTION_POLICY.txt"

    if not policy.exists():

        policy.write_text(
            "COLLECTION POLICY\n\n"
            "1. Prefer official primary sources.\n"
            "2. Keep mirrors labelled as mirrors.\n"
            "3. Preserve original bytes and filenames.\n"
            "4. Save source URLs and SHA-256 hashes.\n"
            "5. Keep OCR, translation and transcripts separate.\n"
            "6. Do not store or redistribute CSAM, intimate victim images,\n"
            "   or unredacted sensitive personal information.\n"
            "7. Record exclusions without retaining restricted contents.\n"
            "8. A person's mention in a document is not proof of wrongdoing.\n",
            encoding="utf-8"
        )

    settings_path = root / "00_ADMIN" / "settings.json"

    if not settings_path.exists():
        write_json(settings_path, DEFAULT_SETTINGS)

    db = open_database(root)

    register_sources(db)

    db.close()


# ============================================================
# DATABASE
# ============================================================

def open_database(root):

    database = root / "06_DATABASE" / "archive.sqlite"

    db = sqlite3.connect(str(database))

    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA foreign_keys=ON")

    db.executescript("""

    CREATE TABLE IF NOT EXISTS sources (

        source_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        tier TEXT NOT NULL,
        url TEXT NOT NULL,
        adapter TEXT NOT NULL,

        active INTEGER DEFAULT 1,

        last_checked TEXT,
        status TEXT,
        notes TEXT

    );

    CREATE TABLE IF NOT EXISTS pages (

        url TEXT PRIMARY KEY,
        source_id TEXT,

        status_code INTEGER,
        last_checked TEXT,

        error TEXT

    );

    CREATE TABLE IF NOT EXISTS items (

        url TEXT PRIMARY KEY,

        discovered_at TEXT,
        last_seen TEXT,

        status_code INTEGER,
        content_type TEXT,

        size_hint INTEGER,
        filename TEXT,

        etag TEXT,
        last_modified TEXT,

        local_path TEXT,
        sha256 TEXT,

        state TEXT,
        error TEXT

    );

    CREATE TABLE IF NOT EXISTS item_sources (

        url TEXT NOT NULL,
        source_id TEXT NOT NULL,

        PRIMARY KEY (url, source_id)

    );

    CREATE TABLE IF NOT EXISTS files (

        local_path TEXT PRIMARY KEY,

        size INTEGER,
        mtime_ns INTEGER,

        baseline_sha256 TEXT,
        observed_sha256 TEXT,

        verified_at TEXT,
        state TEXT,

        source_url TEXT

    );

    CREATE TABLE IF NOT EXISTS archive_members (

        archive_path TEXT,
        member_path TEXT,

        size INTEGER,
        compressed_size INTEGER,

        crc TEXT,
        kind TEXT,

        scanned_at TEXT,

        PRIMARY KEY (archive_path, member_path)

    );

    CREATE TABLE IF NOT EXISTS events (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        at TEXT,
        level TEXT,

        event TEXT,
        url TEXT,

        detail TEXT

    );

    CREATE INDEX IF NOT EXISTS idx_items_state
        ON items(state);

    CREATE INDEX IF NOT EXISTS idx_items_source
        ON item_sources(source_id);

    CREATE INDEX IF NOT EXISTS idx_files_sha
        ON files(baseline_sha256);

    """)

    db.commit()

    return db


def register_sources(db):

    for source in SOURCES:

        sid, name, tier, url, adapter = source

        db.execute(
            """
            INSERT OR IGNORE INTO sources
            (source_id,name,tier,url,adapter)
            VALUES(?,?,?,?,?)
            """,
            (sid, name, tier, url, adapter)
        )

    db.commit()


def log_event(db, level, event_name, url="", detail=""):

    db.execute(
        """
        INSERT INTO events(at,level,event,url,detail)
        VALUES(?,?,?,?,?)
        """,
        (
            now(),
            level,
            event_name,
            url,
            str(detail)[:4000]
        )
    )

    db.commit()


def get_settings(root):

    path = root / "00_ADMIN" / "settings.json"

    settings = dict(DEFAULT_SETTINGS)

    if path.exists():

        try:

            with open(path, encoding="utf-8") as source:
                stored = json.load(source)

            settings.update(stored)

        except Exception:
            pass

    return settings


def save_settings(root, settings):

    write_json(
        root / "00_ADMIN" / "settings.json",
        settings
    )


# ============================================================
# SOURCE MANAGEMENT
# ============================================================

def add_custom_source(db):

    say("\nADD SOURCE")

    name = input("Name: ").strip()
    url = input("URL: ").strip()

    if not name or not url:
        say("Missing name or URL.")
        return

    url = normalize_url(url)

    if not url:
        say("Invalid URL.")
        return

    print("\nTier:")
    print("1. OFFICIAL")
    print("2. MIRROR")
    print("3. SECONDARY")
    print("4. COMMUNITY")

    choice = input("Choice: ").strip()

    tiers = {
        "1": "OFFICIAL",
        "2": "MIRROR",
        "3": "SECONDARY",
        "4": "COMMUNITY"
    }

    tier = tiers.get(choice, "SECONDARY")

    print("\nAdapter:")
    print("1. HTML")
    print("2. Google Drive")
    print("3. Dropbox")
    print("4. Internet Archive")

    adapter_choice = input("Choice: ").strip()

    adapters = {
        "1": "html",
        "2": "google_drive",
        "3": "dropbox",
        "4": "internet_archive"
    }

    adapter = adapters.get(adapter_choice, "html")

    sid = safe_name(
        input("Source ID (Enter = generated): ").strip()
        or name.lower().replace(" ", "_")
    )

    db.execute(
        """
        INSERT OR REPLACE INTO sources
        (source_id,name,tier,url,adapter,active,status)
        VALUES(?,?,?,?,?,1,'REGISTERED')
        """,
        (sid, name, tier, url, adapter)
    )

    db.commit()

    say("Source saved.")


def list_sources(db):

    rows = db.execute(
        """
        SELECT source_id,name,tier,adapter,active,status
        FROM sources
        ORDER BY tier,name
        """
    ).fetchall()

    say("\nSOURCE REGISTRY")

    for row in rows:

        sid, name, tier, adapter, active, status = row

        flag = "ON" if active else "OFF"

        say(
            "%-22s | %-10s | %-15s | %-3s | %s" %
            (
                sid[:22],
                tier,
                adapter,
                flag,
                name
            )
        )


def toggle_source(db):

    list_sources(db)

    sid = input("\nSource ID: ").strip()

    row = db.execute(
        "SELECT active FROM sources WHERE source_id=?",
        (sid,)
    ).fetchone()

    if row is None:
        say("Unknown source.")
        return

    new_value = 0 if row[0] else 1

    db.execute(
        "UPDATE sources SET active=? WHERE source_id=?",
        (new_value, sid)
    )

    db.commit()

    say("Source status updated.")


# ============================================================
# HTTP
# ============================================================

HOST_TIMES = {}
ROBOTS_CACHE = {}


def wait_for_host(url, settings):

    host = urllib.parse.urlsplit(url).netloc.lower()

    delay = float(settings.get("delay", DEFAULT_DELAY))

    last = HOST_TIMES.get(host, 0.0)

    remaining = delay - (time.time() - last)

    if remaining > 0:
        time.sleep(remaining)

    HOST_TIMES[host] = time.time()


def robots_allowed(url, settings):

    if not settings.get("respect_robots", True):
        return True

    parsed = urllib.parse.urlsplit(url)

    host = parsed.netloc.lower()

    if host not in ROBOTS_CACHE:

        robots_url = (
            parsed.scheme + "://" +
            parsed.netloc +
            "/robots.txt"
        )

        parser = urllib.robotparser.RobotFileParser()
        parser.set_url(robots_url)

        try:

            request = urllib.request.Request(
                robots_url,
                headers={
                    "User-Agent": settings.get("user_agent", USER_AGENT)
                }
            )

            with urllib.request.urlopen(
                request,
                timeout=15
            ) as response:

                text = response.read(512 * 1024).decode(
                    "utf-8",
                    errors="replace"
                )

            parser.parse(text.splitlines())

            ROBOTS_CACHE[host] = parser

        except Exception:

            # An unavailable robots file does not mean that the
            # website grants permission to access restricted content.
            # It simply leaves the crawler without robots instructions.

            ROBOTS_CACHE[host] = None

    parser = ROBOTS_CACHE[host]

    if parser is None:
        return True

    return parser.can_fetch(
        settings.get("user_agent", USER_AGENT),
        url
    )


def http_open(url, settings, method="GET", headers=None):

    if not robots_allowed(url, settings):
        raise PermissionError("Blocked by robots.txt")

    wait_for_host(url, settings)

    request_headers = {
        "User-Agent": settings.get("user_agent", USER_AGENT),
        "Accept": "*/*"
    }

    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(
        url,
        headers=request_headers,
        method=method
    )

    return urllib.request.urlopen(
        request,
        timeout=HTTP_TIMEOUT
    )


def get_page(url, settings):

    with http_open(url, settings) as response:

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "html" not in content_type and "xml" not in content_type:

            return (
                response.status,
                content_type,
                b"",
                response.headers
            )

        data = response.read(MAX_HTML_SIZE)

        return (
            response.status,
            content_type,
            data,
            response.headers
        )


# ============================================================
# HTML PARSING
# ============================================================

class PageParser(HTMLParser):

    def __init__(self):

        super().__init__()

        self.links = []
        self.script_urls = []

    def handle_starttag(self, tag, attrs):

        values = dict(attrs)

        if tag.lower() in (
            "a", "area", "iframe", "source", "embed"
        ):

            link = values.get("href") or values.get("src")

            if link:
                self.links.append(link)

        if tag.lower() == "script":

            source = values.get("src")

            if source:
                self.script_urls.append(source)


def extract_urls_from_text(text):

    patterns = [

        r'https?://[^\s"\'<>\\]+',

        r'(?:href|src)\s*=\s*["\']([^"\']+)["\']'

    ]

    found = []

    for pattern in patterns:

        for match in re.findall(pattern, text, re.I):

            if isinstance(match, tuple):
                match = match[0]

            found.append(match)

    return found


def is_download_candidate(url):

    extension = get_extension(url)

    if extension in SUPPORTED_EXTENSIONS:
        return True

    lower = url.lower()

    indicators = (
        "/download",
        "download=",
        "/attachment",
        "attachment=",
        "/document/",
        "/file/"
    )

    return any(
        item in lower
        for item in indicators
    )


# ============================================================
# ITEM INDEX
# ============================================================

def add_item(db, url, source_id):

    url = normalize_url(url)

    if not url:
        return

    db.execute(
        """
        INSERT OR IGNORE INTO items
        (url,discovered_at,last_seen,state)
        VALUES(?,?,?,'DISCOVERED')
        """,
        (
            url,
            now(),
            now()
        )
    )

    db.execute(
        """
        UPDATE items
        SET last_seen=?
        WHERE url=?
        """,
        (now(), url)
    )

    db.execute(
        """
        INSERT OR IGNORE INTO item_sources
        (url,source_id)
        VALUES(?,?)
        """,
        (url, source_id)
    )


# ============================================================
# GOOGLE DRIVE ADAPTER
# ============================================================

def discover_google_drive(db, source, settings):

    sid, name, tier, url, adapter = source

    parsed = urllib.parse.urlsplit(url)

    match = re.search(
        r"/folders/([A-Za-z0-9_-]+)",
        parsed.path
    )

    if not match:

        add_item(db, url, sid)
        return 0, 1

    folder_id = match.group(1)

    embedded = (
        "https://drive.google.com/embeddedfolderview"
        "?id=" + folder_id + "#list"
    )

    say("  Google Drive folder: " + folder_id)

    try:

        status, content_type, data, headers = get_page(
            embedded,
            settings
        )

        text = data.decode(
            "utf-8",
            errors="replace"
        )

        parser = PageParser()
        parser.feed(text)

        identifiers = set()

        patterns = [

            r"/file/d/([A-Za-z0-9_-]{15,})",

            r'"([A-Za-z0-9_-]{20,})"',

            r"[?&]id=([A-Za-z0-9_-]{15,})"

        ]

        for pattern in patterns:

            for item in re.findall(pattern, text):

                if len(item) >= 15:
                    identifiers.add(item)

        for raw in parser.links:

            link = urllib.parse.urljoin(
                embedded,
                raw
            )

            match = re.search(
                r"/file/d/([A-Za-z0-9_-]+)",
                link
            )

            if match:
                identifiers.add(match.group(1))

        count = 0

        for file_id in identifiers:

            download_url = (
                "https://drive.google.com/uc"
                "?export=download&id=" +
                urllib.parse.quote(file_id)
            )

            add_item(
                db,
                download_url,
                sid
            )

            count += 1

        # Keep the original folder reference in the registry.

        db.commit()

        return 1, count

    except Exception as error:

        log_event(
            db,
            "WARN",
            "GOOGLE_DRIVE_DISCOVERY",
            url,
            str(error)
        )

        return 0, 0


# ============================================================
# DROPBOX ADAPTER
# ============================================================

def discover_dropbox(db, source, settings):

    sid, name, tier, url, adapter = source

    parsed = urllib.parse.urlsplit(url)

    query = urllib.parse.parse_qs(parsed.query)

    query["dl"] = ["1"]

    direct = urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query, doseq=True),
            ""
        )
    )

    add_item(
        db,
        direct,
        sid
    )

    return 0, 1


# ============================================================
# INTERNET ARCHIVE ADAPTER
# ============================================================

def discover_internet_archive(db, source, settings):

    sid, name, tier, url, adapter = source

    query = settings.get(
        "internet_archive_query",
        'title:(Epstein) AND mediatype:(texts)'
    )

    rows = int(
        settings.get(
            "internet_archive_rows",
            300
        )
    )

    api = "https://archive.org/advancedsearch.php"

    params = {
        "q": query,
        "fl[]": ["identifier", "title"],
        "rows": str(rows),
        "page": "1",
        "output": "json"
    }

    search_url = api + "?" + urllib.parse.urlencode(
        params,
        doseq=True
    )

    try:

        with http_open(search_url, settings) as response:

            payload = json.loads(
                response.read().decode("utf-8")
            )

        documents = payload.get(
            "response", {}
        ).get("docs", [])

        found = 0

        for document in documents:

            identifier = document.get("identifier")

            if not identifier:
                continue

            metadata_url = (
                "https://archive.org/metadata/" +
                urllib.parse.quote(identifier)
            )

            try:

                with http_open(
                    metadata_url,
                    settings
                ) as response:

                    metadata = json.loads(
                        response.read().decode("utf-8")
                    )

                files = metadata.get("files", [])

                for item in files:

                    filename = item.get("name", "")

                    extension = Path(filename).suffix.lower()

                    if extension not in SUPPORTED_EXTENSIONS:
                        continue

                    if filename.startswith("__MACOSX/"):
                        continue

                    file_url = (
                        "https://archive.org/download/" +
                        urllib.parse.quote(identifier) +
                        "/" +
                        urllib.parse.quote(filename)
                    )

                    add_item(
                        db,
                        file_url,
                        sid
                    )

                    found += 1

            except Exception as error:

                log_event(
                    db,
                    "WARN",
                    "IA_METADATA_ERROR",
                    metadata_url,
                    str(error)
                )

        db.commit()

        return len(documents), found

    except Exception as error:

        log_event(
            db,
            "ERROR",
            "IA_SEARCH_ERROR",
            search_url,
            str(error)
        )

        return 0, 0


# ============================================================
# GENERIC HTML DISCOVERY
# ============================================================

def crawl_html_source(db, source, settings):

    sid, name, tier, start_url, adapter = source

    start_url = normalize_url(start_url)

    if not start_url:
        return 0, 0

    base_host = urllib.parse.urlsplit(
        start_url
    ).netloc.lower()

    depth_limit = min(
        5,
        max(
            0,
            int(settings.get("crawl_depth", DEFAULT_CRAWL_DEPTH))
        )
    )

    page_limit = int(
        settings.get("page_limit", DEFAULT_PAGE_LIMIT)
    )

    queue = [(start_url, 0)]

    visited = set()
    candidate_files = set()

    # Add sitemap as another discovery starting point.

    parsed = urllib.parse.urlsplit(start_url)

    sitemap = (
        parsed.scheme +
        "://" +
        parsed.netloc +
        "/sitemap.xml"
    )

    queue.append((sitemap, 0))

    while queue:

        url, depth = queue.pop(0)

        url = normalize_url(url)

        if not url:
            continue

        if url in visited:
            continue

        if page_limit > 0 and len(visited) >= page_limit:
            break

        visited.add(url)

        if not robots_allowed(url, settings):
            continue

        try:

            status, content_type, data, headers = get_page(
                url,
                settings
            )

            if not data:
                continue

            text = data.decode(
                "utf-8",
                errors="replace"
            )

            parser = PageParser()

            parser.feed(text)

            db.execute(
                """
                INSERT OR REPLACE INTO pages
                (url,source_id,status_code,last_checked,error)
                VALUES(?,?,?,?,NULL)
                """,
                (
                    url,
                    sid,
                    status,
                    now()
                )
            )

            links = list(parser.links)

            # URLs embedded in page source.
            links.extend(
                extract_urls_from_text(text)
            )

            # JavaScript files are not executed.
            # Their source may contain API paths and document URLs.

            for script in parser.script_urls[:30]:

                script_url = urllib.parse.urljoin(
                    url,
                    script
                )

                try:

                    with http_open(
                        script_url,
                        settings
                    ) as response:

                        script_text = response.read(
                            2 * 1024 * 1024
                        ).decode(
                            "utf-8",
                            errors="replace"
                        )

                    links.extend(
                        extract_urls_from_text(script_text)
                    )

                except Exception:
                    pass

            for raw in links:

                link = urllib.parse.urljoin(
                    url,
                    html.unescape(raw)
                )

                link = normalize_url(link)

                if not link:
                    continue

                if is_download_candidate(link):

                    candidate_files.add(link)
                    continue

                link_host = urllib.parse.urlsplit(
                    link
                ).netloc.lower()

                if (
                    link_host == base_host
                    and depth < depth_limit
                ):

                    queue.append(
                        (link, depth + 1)
                    )

        except urllib.error.HTTPError as error:

            db.execute(
                """
                INSERT OR REPLACE INTO pages
                (url,source_id,status_code,last_checked,error)
                VALUES(?,?,?,?,?)
                """,
                (
                    url,
                    sid,
                    error.code,
                    now(),
                    str(error)
                )
            )

            level = (
                "CRITICAL"
                if error.code in CRITICAL_HTTP_CODES
                else "WARN"
            )

            log_event(
                db,
                level,
                "DISCOVERY_HTTP_ERROR",
                url,
                str(error)
            )

        except Exception as error:

            log_event(
                db,
                "WARN",
                "DISCOVERY_ERROR",
                url,
                str(error)
            )

        db.commit()

    for link in candidate_files:

        add_item(
            db,
            link,
            sid
        )

    db.commit()

    return len(visited), len(candidate_files)


# ============================================================
# DISCOVERY DISPATCHER
# ============================================================

def discover_source(db, source, settings):

    adapter = source[4]

    if adapter == "google_drive":

        return discover_google_drive(
            db,
            source,
            settings
        )

    if adapter == "dropbox":

        return discover_dropbox(
            db,
            source,
            settings
        )

    if adapter == "internet_archive":

        return discover_internet_archive(
            db,
            source,
            settings
        )

    return crawl_html_source(
        db,
        source,
        settings
    )


def discover_all(db, settings):

    say("\nDISCOVERY")

    sources = db.execute(
        """
        SELECT source_id,name,tier,url,adapter
        FROM sources
        WHERE active=1
        ORDER BY tier,name
        """
    ).fetchall()

    total_pages = 0
    total_files = 0

    for index, source in enumerate(sources, 1):

        sid, name, tier, url, adapter = source

        say(
            "\n[%d/%d] %s" %
            (index, len(sources), name)
        )

        pages, files = discover_source(
            db,
            source,
            settings
        )

        total_pages += pages
        total_files += files

        db.execute(
            """
            UPDATE sources
            SET last_checked=?,status='CHECKED'
            WHERE source_id=?
            """,
            (now(), sid)
        )

        db.commit()

        say(
            "  Pages: %d | candidate files: %d" %
            (pages, files)
        )

    say("\nDISCOVERY TOTALS")

    say("  Pages: " + str(total_pages))
    say("  Candidate URLs: " + str(total_files))


# ============================================================
# NETWORK PROBES
# ============================================================

def probe_url(url, settings):

    try:

        with http_open(
            url,
            settings,
            method="HEAD"
        ) as response:

            return (
                response.status,
                response.headers.get("Content-Type", ""),
                int(response.headers.get("Content-Length") or 0),
                response.headers.get("ETag"),
                response.headers.get("Last-Modified"),
                response.headers.get("Content-Disposition"),
                None
            )

    except urllib.error.HTTPError as error:

        if error.code not in (400, 403, 405, 501):

            return (
                error.code,
                "",
                0,
                None,
                None,
                None,
                str(error)
            )

    except Exception:
        pass

    # Range request fallback for servers that reject HEAD.

    try:

        with http_open(
            url,
            settings,
            headers={
                "Range": "bytes=0-0"
            }
        ) as response:

            return (
                response.status,
                response.headers.get("Content-Type", ""),
                int(response.headers.get("Content-Length") or 0),
                response.headers.get("ETag"),
                response.headers.get("Last-Modified"),
                response.headers.get("Content-Disposition"),
                None
            )

    except urllib.error.HTTPError as error:

        return (
            error.code,
            "",
            0,
            None,
            None,
            None,
            str(error)
        )

    except Exception as error:

        return (
            0,
            "",
            0,
            None,
            None,
            None,
            str(error)
        )


def probe_all(db, settings):

    say("\nNETWORK PROBES")

    items = db.execute(
        """
        SELECT url
        FROM items
        ORDER BY url
        """
    ).fetchall()

    for index, (url,) in enumerate(items, 1):

        (
            status,
            content_type,
            size,
            etag,
            modified,
            disposition,
            error
        ) = probe_url(
            url,
            settings
        )

        if status in (200, 206):
            state = "READY"

        elif status in CRITICAL_HTTP_CODES:
            state = "CRITICAL"

        else:
            state = "ERROR"

        filename = parse_content_disposition(
            disposition
        )

        db.execute(
            """
            UPDATE items

            SET status_code=?,
                content_type=?,
                size_hint=?,
                etag=?,
                last_modified=?,
                filename=COALESCE(?,filename),
                last_seen=?,
                state=?,
                error=?

            WHERE url=?
            """,
            (
                status or None,
                content_type,
                size or None,
                etag,
                modified,
                filename,
                now(),
                state,
                error,
                url
            )
        )

        if state != "READY":

            log_event(
                db,
                state,
                "NETWORK_PROBE",
                url,
                "HTTP %s: %s" % (status, error or "")
            )

        if index % 25 == 0:

            db.commit()

            say(
                "  %d / %d" %
                (index, len(items))
            )

    db.commit()

    say("Probe pass complete.")


# ============================================================
# FILE DESTINATION
# ============================================================

def destination_folder(root, tier, source_id):

    if tier == "OFFICIAL":

        if source_id.startswith("fbi"):
            folder = "01_RAW_OFFICIAL/FBI"

        elif source_id.startswith("cbp"):
            folder = "01_RAW_OFFICIAL/CBP"

        elif source_id.startswith("house"):
            folder = "01_RAW_OFFICIAL/HOUSE_OVERSIGHT"

        elif source_id.startswith("senate"):
            folder = "01_RAW_OFFICIAL/SENATE_FINANCE"

        elif source_id.startswith("florida"):
            folder = "01_RAW_OFFICIAL/FLORIDA"

        elif source_id.startswith("usvi"):
            folder = "01_RAW_OFFICIAL/US_VIRGIN_ISLANDS"

        elif source_id.startswith("doj_oig"):
            folder = "01_RAW_OFFICIAL/DOJ_OIG"

        elif source_id.startswith("doj_opr"):
            folder = "01_RAW_OFFICIAL/DOJ_OPR"

        elif source_id.startswith("bop"):
            folder = "01_RAW_OFFICIAL/BOP"

        elif source_id.startswith("bush"):
            folder = "01_RAW_OFFICIAL/PRESIDENTIAL_LIBRARIES"

        elif source_id.startswith("sec"):
            folder = "01_RAW_OFFICIAL/SEC"

        else:
            folder = "01_RAW_OFFICIAL/DOJ"

    elif tier == "COMMUNITY":

        folder = "04_COMMUNITY_RESEARCH/FORUMS"

    elif source_id == "internet_archive":

        folder = "03_SECONDARY_ARCHIVES/INTERNET_ARCHIVE"

    elif source_id == "courtlistener":

        folder = "03_SECONDARY_ARCHIVES/COURTLISTENER"

    elif source_id == "google_pinpoint":

        folder = "03_SECONDARY_ARCHIVES/GOOGLE_PINPOINT"

    elif source_id == "epstein_project":

        folder = "03_SECONDARY_ARCHIVES/EPSTEIN_PROJECT"

    elif source_id == "epstein_exposed":

        folder = "03_SECONDARY_ARCHIVES/EPSTEIN_EXPOSED"

    else:

        folder = "03_SECONDARY_ARCHIVES/OTHER_MIRRORS"

    result = root / folder / safe_name(source_id)

    result.mkdir(
        parents=True,
        exist_ok=True
    )

    return result


# ============================================================
# DEDUPLICATION
# ============================================================

def find_existing_hash(db, digest):

    return db.execute(
        """
        SELECT local_path
        FROM files
        WHERE baseline_sha256=?
          AND state='VERIFIED'
        LIMIT 1
        """,
        (digest,)
    ).fetchone()


def register_file(
    db,
    relative_path,
    size,
    digest,
    source_url
):

    path = Path(relative_path)

    absolute = path

    try:
        stat = absolute.stat()
        mtime_ns = stat.st_mtime_ns
    except OSError:
        mtime_ns = None

    db.execute(
        """
        INSERT OR REPLACE INTO files
        (
            local_path,
            size,
            mtime_ns,
            baseline_sha256,
            observed_sha256,
            verified_at,
            state,
            source_url
        )
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (
            str(relative_path),
            size,
            mtime_ns,
            digest,
            digest,
            now(),
            "VERIFIED",
            source_url
        )
    )


# ============================================================
# DOWNLOAD ENGINE
# ============================================================

def download_item(db, root, row, settings):

    url, source_id, tier, size_hint, old_path = row

    extension = get_extension(url)

    if (
        extension in MEDIA_EXTENSIONS
        and not settings.get("include_media", False)
    ):

        db.execute(
            """
            UPDATE items
            SET state='HOLD_MEDIA',
                error='Media requires manual review'
            WHERE url=?
            """,
            (url,)
        )

        db.commit()

        return "held"

    folder = destination_folder(
        root,
        tier or "SECONDARY",
        source_id or "unknown"
    )

    staging = root / "99_STAGING" / "DOWNLOADING"

    staging.mkdir(
        parents=True,
        exist_ok=True
    )

    key = url_hash(url)

    partial = staging / (key + ".part")

    offset = partial.stat().st_size if partial.exists() else 0

    headers = {}

    if offset:
        headers["Range"] = "bytes=%d-" % offset

    retries = int(
        settings.get("retries", DEFAULT_RETRIES)
    )

    last_error = None

    for attempt in range(retries):

        try:

            with http_open(
                url,
                settings,
                headers=headers
            ) as response:

                status = response.status

                if offset and status != 206:

                    partial.unlink(missing_ok=True)
                    offset = 0
                    headers = {}

                    continue

                if offset and status == 206:

                    content_range = response.headers.get(
                        "Content-Range",
                        ""
                    )

                    match = re.match(
                        r"bytes\s+(\d+)-",
                        content_range
                    )

                    if match and int(match.group(1)) != offset:

                        partial.unlink(missing_ok=True)
                        offset = 0
                        headers = {}

                        continue

                mode = "ab" if offset else "wb"

                digest = hashlib.sha256()

                if offset:

                    with open(partial, "rb") as old:

                        while True:

                            block = old.read(BLOCK_SIZE)

                            if not block:
                                break

                            digest.update(block)

                with open(partial, mode) as output:

                    while True:

                        block = response.read(BLOCK_SIZE)

                        if not block:
                            break

                        output.write(block)

                        digest.update(block)

                checksum = digest.hexdigest()

                actual_size = partial.stat().st_size

                # Detect a server returning HTML instead of a file.

                content_type = response.headers.get(
                    "Content-Type",
                    ""
                ).lower()

                with open(partial, "rb") as check:

                    first_bytes = check.read(512).lstrip().lower()

                looks_like_html = (
                    first_bytes.startswith(b"<!doctype html")
                    or first_bytes.startswith(b"<html")
                    or first_bytes.startswith(b"<head")
                )

                if (
                    looks_like_html
                    and extension in SUPPORTED_EXTENSIONS
                    and extension not in (".html", ".htm")
                ):

                    quarantine = (
                        root / "99_STAGING" /
                        "QUARANTINE" /
                        (key + ".html")
                    )

                    quarantine.parent.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                    os.replace(
                        partial,
                        quarantine
                    )

                    db.execute(
                        """
                        UPDATE items
                        SET state='QUARANTINED',
                            error='HTML returned instead of expected file'
                        WHERE url=?
                        """,
                        (url,)
                    )

                    db.commit()

                    log_event(
                        db,
                        "WARN",
                        "HTML_INSTEAD_OF_FILE",
                        url,
                        str(quarantine)
                    )

                    return "error"

                # Duplicate content check.

                duplicate = find_existing_hash(
                    db,
                    checksum
                )

                if duplicate:

                    existing_relative = duplicate[0]
                    existing_path = root / existing_relative

                    if existing_path.exists():

                        partial.unlink(missing_ok=True)

                        db.execute(
                            """
                            UPDATE items
                            SET local_path=?,
                                sha256=?,
                                size_hint=?,
                                state='DUPLICATE',
                                error=NULL
                            WHERE url=?
                            """,
                            (
                                existing_relative,
                                checksum,
                                actual_size,
                                url
                            )
                        )

                        db.commit()

                        log_event(
                            db,
                            "INFO",
                            "DUPLICATE",
                            url,
                            existing_relative
                        )

                        return "duplicate"

                # Name priority:
                # Content-Disposition > existing filename > URL path.

                filename = parse_content_disposition(
                    response.headers.get("Content-Disposition")
                )

                if not filename:

                    row_name = db.execute(
                        "SELECT filename FROM items WHERE url=?",
                        (url,)
                    ).fetchone()

                    if row_name and row_name[0]:
                        filename = safe_name(row_name[0])
                    else:
                        filename = filename_from_url(url)

                destination = folder / filename

                if destination.exists():

                    suffix = checksum[:12]

                    destination = folder / (
                        destination.stem +
                        "_" +
                        suffix +
                        destination.suffix
                    )

                os.replace(
                    partial,
                    destination
                )

                relative = str(
                    destination.relative_to(root)
                )

                db.execute(
                    """
                    UPDATE items

                    SET local_path=?,
                        sha256=?,
                        size_hint=?,
                        content_type=?,
                        filename=?,
                        state='DOWNLOADED',
                        last_seen=?,
                        error=NULL

                    WHERE url=?
                    """,
                    (
                        relative,
                        checksum,
                        actual_size,
                        content_type,
                        destination.name,
                        now(),
                        url
                    )
                )

                db.commit()

                stat = destination.stat()

                db.execute(
                    """
                    INSERT OR REPLACE INTO files
                    (
                        local_path,
                        size,
                        mtime_ns,
                        baseline_sha256,
                        observed_sha256,
                        verified_at,
                        state,
                        source_url
                    )
                    VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        relative,
                        actual_size,
                        stat.st_mtime_ns,
                        checksum,
                        checksum,
                        now(),
                        "VERIFIED",
                        url
                    )
                )

                db.commit()

                log_event(
                    db,
                    "INFO",
                    "DOWNLOAD_OK",
                    url,
                    "%s | %s | SHA256=%s" %
                    (
                        relative,
                        human_size(actual_size),
                        checksum
                    )
                )

                return "downloaded"

        except urllib.error.HTTPError as error:

            last_error = "HTTP %d: %s" % (
                error.code,
                error
            )

            if error.code in CRITICAL_HTTP_CODES:

                db.execute(
                    """
                    UPDATE items
                    SET status_code=?,
                        state='CRITICAL',
                        last_seen=?,
                        error=?
                    WHERE url=?
                    """,
                    (
                        error.code,
                        now(),
                        last_error,
                        url
                    )
                )

                db.commit()

                log_event(
                    db,
                    "CRITICAL",
                    "DOWNLOAD_HTTP_ERROR",
                    url,
                    last_error
                )

                return "critical"

        except Exception as error:

            last_error = repr(error)

        time.sleep(
            1 + attempt * 2
        )

    db.execute(
        """
        UPDATE items
        SET state='ERROR',
            last_seen=?,
            error=?
        WHERE url=?
        """,
        (
            now(),
            last_error,
            url
        )
    )

    db.commit()

    log_event(
        db,
        "ERROR",
        "DOWNLOAD_FAILED",
        url,
        last_error or "Unknown error"
    )

    return "error"


# ============================================================
# DISK / FILE HEALTH
# ============================================================

def mount_point(path):

    current = Path(path).resolve()

    while current.parent != current:

        if os.path.ismount(str(current)):
            return current

        current = current.parent

    return current


def disk_report(root):

    usage = shutil.disk_usage(
        str(root)
    )

    mount = mount_point(root)

    say("\nDISK SPACE")

    say("  Mount: " + str(mount))
    say("  Total: " + human_size(usage.total))
    say("  Used:  " + human_size(usage.used))
    say("  Free:  " + human_size(usage.free))

    try:

        entries = list(mount.iterdir())

        directories = [
            entry.name for entry in entries
            if entry.is_dir()
        ]

        say(
            "  Directories at mount level: %d" %
            len(directories)
        )

    except Exception as error:

        say("  Directory listing failed: " + str(error))

    return usage


def smart_report(root, explicit_device=None):

    say("\nSMART HEALTH")

    say("  No filesystem repair will be run.")

    smartctl = shutil.which("smartctl")

    if not smartctl:

        say("  smartctl not installed.")
        say("  Install smartmontools for SMART information.")

        return

    device = explicit_device

    if not device:

        system = platform.system().lower()

        try:

            if system == "linux" and shutil.which("findmnt"):

                device = subprocess.check_output(
                    [
                        "findmnt",
                        "-no",
                        "SOURCE",
                        "--target",
                        str(root)
                    ],
                    text=True,
                    stderr=subprocess.DEVNULL
                ).strip()

            elif system == "darwin" and shutil.which("df"):

                line = subprocess.check_output(
                    ["df", str(root)],
                    text=True,
                    stderr=subprocess.DEVNULL
                ).splitlines()[-1]

                device = line.split()[0]

        except Exception:

            device = None

    if not device:

        say("  Device not identified; SMART skipped.")
        return

    say("  Device: " + device)

    try:

        result = subprocess.run(
            [
                smartctl,
                "-H",
                device
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )

        for line in result.stdout.splitlines()[:25]:
            say("  " + line)

    except Exception as error:

        say("  SMART error: " + str(error))


def quick_write_test(root):

    directory = root / "99_STAGING"

    directory.mkdir(
        parents=True,
        exist_ok=True
    )

    path = directory / ".write_test"

    try:

        with open(path, "wb") as output:
            output.write(b"ARCHIVE_WRITE_TEST")
            output.flush()
            os.fsync(output.fileno())

        path.unlink(missing_ok=True)

        say("  Write test: OK")

    except Exception as error:

        say("  Write test failed: " + str(error))


# ============================================================
# VERIFY FILES
# ============================================================

def verify_local_files(db, root):

    say("\nLOCAL FILE VERIFICATION")

    checked = 0
    new_files = 0
    changed = 0
    missing = 0
    errors = 0

    known = {
        row[0]: row[1]
        for row in db.execute(
            """
            SELECT local_path,baseline_sha256
            FROM files
            """
        ).fetchall()
    }

    seen = set()

    for directory in DATA_DIRECTORIES:

        base_directory = root / directory

        if not base_directory.exists():
            continue

        for base, dirs, files in os.walk(
            base_directory,
            followlinks=False
        ):

            dirs[:] = [
                name for name in dirs
                if name not in IGNORE_SCAN_DIRECTORIES
            ]

            for filename in files:

                if filename.endswith(".part"):
                    continue

                path = Path(base) / filename

                try:

                    if not path.is_file():
                        continue

                    relative = str(
                        path.relative_to(root)
                    )

                    seen.add(relative)

                    stat = path.stat()

                    digest = file_sha256(path)

                    previous = known.get(relative)

                    if previous is None:

                        state = "NEW"
                        new_files += 1

                        db.execute(
                            """
                            INSERT OR REPLACE INTO files
                            (
                                local_path,
                                size,
                                mtime_ns,
                                baseline_sha256,
                                observed_sha256,
                                verified_at,
                                state
                            )
                            VALUES(?,?,?,?,?,?,?)
                            """,
                            (
                                relative,
                                stat.st_size,
                                stat.st_mtime_ns,
                                digest,
                                digest,
                                now(),
                                state
                            )
                        )

                    elif digest != previous:

                        state = "CORRUPT"
                        changed += 1

                        # The original baseline is preserved.
                        # Do not overwrite it with a changed checksum.

                        db.execute(
                            """
                            UPDATE files
                            SET observed_sha256=?,
                                verified_at=?,
                                state=?
                            WHERE local_path=?
                            """,
                            (
                                digest,
                                now(),
                                state,
                                relative
                            )
                        )

                        log_event(
                            db,
                            "CRITICAL",
                            "CHECKSUM_MISMATCH",
                            "",
                            relative
                        )

                    else:

                        state = "VERIFIED"

                        db.execute(
                            """
                            UPDATE files
                            SET observed_sha256=?,
                                verified_at=?,
                                state=?,
                                size=?,
                                mtime_ns=?
                            WHERE local_path=?
                            """,
                            (
                                digest,
                                now(),
                                state,
                                stat.st_size,
                                stat.st_mtime_ns,
                                relative
                            )
                        )

                    checked += 1

                except Exception as error:

                    errors += 1

                    log_event(
                        db,
                        "ERROR",
                        "FILE_READ_ERROR",
                        str(path),
                        str(error)
                    )

        db.commit()

    for relative in known:

        if relative not in seen:

            missing += 1

            db.execute(
                """
                UPDATE files
                SET state='MISSING',
                    verified_at=?
                WHERE local_path=?
                """,
                (
                    now(),
                    relative
                )
            )

    db.commit()

    say("  Checked:   " + str(checked))
    say("  New:       " + str(new_files))
    say("  Changed:   " + str(changed))
    say("  Missing:   " + str(missing))
    say("  Errors:    " + str(errors))

    return {
        "checked": checked,
        "new": new_files,
        "changed": changed,
        "missing": missing,
        "errors": errors
    }


def rebaseline_file(db, root):

    rows = db.execute(
        """
        SELECT local_path,state
        FROM files
        WHERE state='CORRUPT'
        """
    ).fetchall()

    if not rows:

        say("No changed files.")
        return

    say("\nCHANGED FILES")

    for index, row in enumerate(rows, 1):

        say(
            "%d. %s [%s]" %
            (index, row[0], row[1])
        )

    answer = input(
        "\nRecalculate and replace old baselines? [y/N] "
    ).strip().lower()

    if answer not in ("y", "yes", "да", "д"):
        return

    for relative, state in rows:

        path = root / relative

        if not path.exists():
            continue

        digest = file_sha256(path)

        stat = path.stat()

        db.execute(
            """
            UPDATE files
            SET baseline_sha256=?,
                observed_sha256=?,
                size=?,
                mtime_ns=?,
                verified_at=?,
                state='VERIFIED'
            WHERE local_path=?
            """,
            (
                digest,
                digest,
                stat.st_size,
                stat.st_mtime_ns,
                now(),
                relative
            )
        )

    db.commit()

    say("Baselines updated.")


# ============================================================
# ARCHIVE INVENTORY
# ============================================================

def inspect_zip(db, root, path, relative):

    try:

        with zipfile.ZipFile(path, "r") as archive:

            bad = archive.testzip()

            for member in archive.infolist():

                db.execute(
                    """
                    INSERT OR REPLACE INTO archive_members
                    (
                        archive_path,
                        member_path,
                        size,
                        compressed_size,
                        crc,
                        kind,
                        scanned_at
                    )
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        relative,
                        member.filename,
                        member.file_size,
                        member.compress_size,
                        "%08x" % member.CRC,
                        "DIRECTORY" if member.is_dir() else "FILE",
                        now()
                    )
                )

            db.commit()

            if bad:

                log_event(
                    db,
                    "CRITICAL",
                    "ZIP_CRC_ERROR",
                    "",
                    relative + " -> " + bad
                )

                return "CORRUPT"

            return "OK"

    except Exception as error:

        log_event(
            db,
            "ERROR",
            "ZIP_READ_ERROR",
            "",
            relative + " | " + str(error)
        )

        return "ERROR"


def inspect_tar(db, root, path, relative):

    try:

        with tarfile.open(path, "r:*") as archive:

            for member in archive:

                if not member.isfile() and not member.isdir():
                    kind = "SPECIAL"
                elif member.isdir():
                    kind = "DIRECTORY"
                else:
                    kind = "FILE"

                db.execute(
                    """
                    INSERT OR REPLACE INTO archive_members
                    (
                        archive_path,
                        member_path,
                        size,
                        compressed_size,
                        crc,
                        kind,
                        scanned_at
                    )
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        relative,
                        member.name,
                        member.size,
                        None,
                        None,
                        kind,
                        now()
                    )
                )

            db.commit()

        return "OK"

    except Exception as error:

        log_event(
            db,
            "ERROR",
            "TAR_READ_ERROR",
            "",
            relative + " | " + str(error)
        )

        return "ERROR"


def inspect_archives(db, root):

    say("\nARCHIVE INVENTORY")

    checked = 0

    for directory in DATA_DIRECTORIES:

        base_directory = root / directory

        if not base_directory.exists():
            continue

        for base, dirs, files in os.walk(base_directory):

            for filename in files:

                path = Path(base) / filename

                extension = path.suffix.lower()

                if extension not in (
                    ".zip",
                    ".tar",
                    ".gz",
                    ".tgz",
                    ".bz2"
                ):
                    continue

                relative = str(
                    path.relative_to(root)
                )

                say("  " + relative)

                if extension == ".zip":

                    state = inspect_zip(
                        db,
                        root,
                        path,
                        relative
                    )

                else:

                    state = inspect_tar(
                        db,
                        root,
                        path,
                        relative
                    )

                say("    " + state)

                checked += 1

    say("Archives inspected: " + str(checked))

    return checked


# ============================================================
# DOWNLOAD ESTIMATE
# ============================================================

def download_estimate(db, root, settings):

    rows = db.execute(
        """
        SELECT url,COALESCE(size_hint,0),state
        FROM items
        WHERE local_path IS NULL
        """
    ).fetchall()

    count = 0
    total = 0
    unknown = 0
    held = 0

    for url, size, state in rows:

        extension = get_extension(url)

        if (
            extension in MEDIA_EXTENSIONS
            and not settings.get("include_media", False)
        ):

            held += 1
            continue

        if state == "HOLD_MEDIA":
            held += 1
            continue

        count += 1
        total += size

        if size <= 0:
            unknown += 1

    disk = shutil.disk_usage(
        str(root)
    )

    say("\nDOWNLOAD ESTIMATE")

    say("  Pending: " + str(count))
    say("  Known size: " + human_size(total))
    say("  Unknown size: " + str(unknown))
    say("  Held media: " + str(held))
    say("  Free space: " + human_size(disk.free))

    if total > disk.free:

        say("\nWARNING: Known download size exceeds free space.")

    if unknown:

        say("WARNING: Some file sizes are unknown.")

    return count, total, unknown


# ============================================================
# DOWNLOAD QUEUE
# ============================================================

def download_pending(db, root, settings):

    rows = db.execute(
        """
        SELECT
            items.url,
            item_sources.source_id,
            sources.tier,
            items.size_hint,
            items.local_path

        FROM items

        JOIN item_sources
            ON item_sources.url=items.url

        JOIN sources
            ON sources.source_id=item_sources.source_id

        WHERE items.local_path IS NULL
          AND items.state NOT IN (
              'HOLD_MEDIA',
              'QUARANTINED'
          )

        ORDER BY
            sources.tier,
            item_sources.source_id,
            items.url
        """
    ).fetchall()

    # When multiple sources point to the same URL, the query may duplicate
    # its record. Keep one source association for this download pass.

    unique = {}
    for row in rows:
        unique.setdefault(row[0], row)

    rows = list(unique.values())

    results = {
        "downloaded": 0,
        "duplicate": 0,
        "critical": 0,
        "error": 0,
        "held": 0
    }

    say("\nDOWNLOAD QUEUE")
    say("  Items: " + str(len(rows)))

    for index, row in enumerate(rows, 1):

        result = download_item(
            db,
            root,
            row,
            settings
        )

        results[result] = results.get(result, 0) + 1

        if index % 10 == 0:

            say(
                "  %d/%d | downloaded=%d | duplicate=%d | errors=%d" %
                (
                    index,
                    len(rows),
                    results["downloaded"],
                    results["duplicate"],
                    results["error"]
                )
            )

    say("\nDOWNLOAD RESULTS")

    for key, value in results.items():
        say("  %-12s %d" % (key, value))

    critical_count = db.execute(
        """
        SELECT COUNT(*)
        FROM items
        WHERE state='CRITICAL'
        """
    ).fetchone()[0]

    if critical_count:

        say(
            "\nCritical failures: %d" %
            critical_count
        )

        say(
            "A critical failure does not block the remaining downloads."
        )

        answer = input(
            "Retry critical URLs now? [y/N] "
        ).strip().lower()

        if answer in ("y", "yes", "да", "д"):

            retry_critical(db, root, settings)

    verify_local_files(db, root)


def retry_critical(db, root, settings):

    rows = db.execute(
        """
        SELECT
            items.url,
            item_sources.source_id,
            sources.tier,
            items.size_hint,
            items.local_path

        FROM items

        JOIN item_sources
            ON item_sources.url=items.url

        JOIN sources
            ON sources.source_id=item_sources.source_id

        WHERE items.state IN (
            'CRITICAL',
            'ERROR'
        )

        ORDER BY items.url
        """
    ).fetchall()

    unique = {}

    for row in rows:
        unique.setdefault(row[0], row)

    rows = list(unique.values())

    say(
        "Retry candidates: " + str(len(rows))
    )

    for row in rows:

        download_item(
            db,
            root,
            row,
            settings
        )


# ============================================================
# MANIFEST EXPORT
# ============================================================

def export_manifests(db, root):

    say("\nEXPORTING MANIFESTS")

    fields = [

        "url",
        "source_id",
        "tier",

        "status_code",
        "content_type",

        "size_hint",
        "filename",

        "local_path",
        "sha256",

        "state",
        "error"
    ]

    rows = db.execute(
        """
        SELECT
            items.url,
            item_sources.source_id,
            sources.tier,

            items.status_code,
            items.content_type,

            items.size_hint,
            items.filename,

            items.local_path,
            items.sha256,

            items.state,
            items.error

        FROM items

        LEFT JOIN item_sources
            ON item_sources.url=items.url

        LEFT JOIN sources
            ON sources.source_id=item_sources.source_id

        ORDER BY item_sources.source_id,items.url
        """
    ).fetchall()

    path = root / "07_MANIFESTS" / "master_manifest.jsonl"

    with open(path, "w", encoding="utf-8") as output:

        for row in rows:

            record = dict(zip(fields, row))

            output.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                ) + "\n"
            )

    failures = db.execute(
        """
        SELECT
            url,
            status_code,
            state,
            error

        FROM items

        WHERE state IN (
            'CRITICAL',
            'ERROR',
            'MISSING',
            'CORRUPT',
            'QUARANTINED'
        )

        ORDER BY state,url
        """
    ).fetchall()

    failure_data = []

    for url, status, state, error in failures:

        failure_data.append(
            {
                "url": url,
                "status_code": status,
                "state": state,
                "error": error
            }
        )

    write_json(
        root / "07_MANIFESTS" / "critical_failures.json",
        failure_data
    )

    source_rows = db.execute(
        """
        SELECT source_id,name,tier,url,adapter,active,status,last_checked
        FROM sources
        ORDER BY tier,name
        """
    ).fetchall()

    source_fields = [
        "source_id",
        "name",
        "tier",
        "url",
        "adapter",
        "active",
        "status",
        "last_checked"
    ]

    write_json(
        root / "07_MANIFESTS" / "sources.json",
        [
            dict(zip(source_fields, row))
            for row in source_rows
        ]
    )

    say("  URLs: " + str(len(rows)))
    say("  Failures: " + str(len(failure_data)))


# ============================================================
# STATUS REPORT
# ============================================================

def show_status(db):

    say("\nARCHIVE STATUS")

    rows = db.execute(
        """
        SELECT state,COUNT(*)
        FROM items
        GROUP BY state
        ORDER BY state
        """
    ).fetchall()

    for state, count in rows:

        say(
            "  %-18s %d" %
            (state, count)
        )

    file_rows = db.execute(
        """
        SELECT state,COUNT(*)
        FROM files
        GROUP BY state
        ORDER BY state
        """
    ).fetchall()

    say("\nLOCAL FILES")

    for state, count in file_rows:

        say(
            "  %-18s %d" %
            (state, count)
        )


# ============================================================
# OCR
# ============================================================

def command_exists(name):

    return shutil.which(name) is not None


def output_name_for(path):

    name = safe_name(path.stem)

    return name[:150]


def ocr_image(path, output, languages):

    tesseract = shutil.which("tesseract")

    if not tesseract:

        raise RuntimeError(
            "tesseract not installed"
        )

    result = subprocess.run(
        [
            tesseract,
            str(path),
            "stdout",
            "-l",
            languages
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=None
    )

    if result.returncode != 0:

        raise RuntimeError(
            result.stderr.decode(
                "utf-8",
                errors="replace"
            )
        )

    output.write_bytes(
        result.stdout
    )


def extract_pdf_text(path, output):

    pdftotext = shutil.which("pdftotext")

    if not pdftotext:
        return False

    result = subprocess.run(
        [
            pdftotext,
            "-layout",
            str(path),
            "-"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=None
    )

    if result.returncode != 0:
        return False

    text = result.stdout.decode(
        "utf-8",
        errors="replace"
    )

    if not text.strip():
        return False

    output.write_text(
        text,
        encoding="utf-8"
    )

    return True


def ocr_pdf(path, output_dir, languages):

    pdftoppm = shutil.which("pdftoppm")
    tesseract = shutil.which("tesseract")

    if not pdftoppm or not tesseract:

        raise RuntimeError(
            "PDF OCR requires pdftoppm and tesseract"
        )

    base_name = output_name_for(path)

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    text_output = output_dir / (
        base_name + ".txt"
    )

    # First try normal text extraction.

    if extract_pdf_text(
        path,
        text_output
    ):

        return "EXTRACTED_TEXT"

    pdfinfo = shutil.which("pdfinfo")

    if not pdfinfo:

        raise RuntimeError(
            "pdfinfo is required for page enumeration"
        )

    info = subprocess.run(
        [
            pdfinfo,
            str(path)
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=None
    )

    page_match = re.search(
        r"^Pages:\s+(\d+)",
        info.stdout,
        re.M
    )

    if not page_match:

        raise RuntimeError(
            "Could not determine PDF page count"
        )

    page_count = int(page_match.group(1))

    all_text = []

    with tempfile.TemporaryDirectory() as temporary:

        temporary = Path(temporary)

        for page in range(1, page_count + 1):

            prefix = temporary / "page"

            subprocess.run(
                [
                    pdftoppm,
                    "-f", str(page),
                    "-l", str(page),
                    "-r", "200",
                    "-png",
                    str(path),
                    str(prefix)
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=None
            )

            images = list(
                temporary.glob("page-*.png")
            )

            if not images:
                continue

            image_path = images[-1]

            result = subprocess.run(
                [
                    tesseract,
                    str(image_path),
                    "stdout",
                    "-l",
                    languages
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=None
            )

            if result.returncode == 0:

                page_text = result.stdout.decode(
                    "utf-8",
                    errors="replace"
                )

                all_text.append(
                    "\n\n===== PAGE %d =====\n\n%s" %
                    (page, page_text)
                )

            if page % 25 == 0:

                say(
                    "  OCR page %d / %d" %
                    (page, page_count)
                )

    text_output.write_text(
        "\n".join(all_text),
        encoding="utf-8"
    )

    return "OCR"


def run_ocr(root, db, settings):

    say("\nOCR")

    languages = settings.get(
        "ocr_languages",
        "eng+rus"
    )

    tesseract = shutil.which("tesseract")

    if not tesseract:

        say("Tesseract not installed.")
        say("Install Tesseract before using OCR.")
        return

    processed = 0
    failed = 0

    for directory in DATA_DIRECTORIES:

        base_directory = root / directory

        if not base_directory.exists():
            continue

        for base, dirs, files in os.walk(base_directory):

            for filename in files:

                path = Path(base) / filename

                extension = path.suffix.lower()

                if extension not in (
                    ".pdf",
                    ".jpg",
                    ".jpeg",
                    ".png",
                    ".tif",
                    ".tiff",
                    ".bmp",
                    ".webp"
                ):
                    continue

                relative = path.relative_to(root)

                output_dir = (
                    root /
                    "05_DERIVED" /
                    "OCR" /
                    relative.parent
                )

                output_dir.mkdir(
                    parents=True,
                    exist_ok=True
                )

                output_name = output_name_for(path)

                output = output_dir / (
                    output_name + ".txt"
                )

                if output.exists():
                    continue

                say("  " + str(relative))

                try:

                    if extension == ".pdf":

                        method = ocr_pdf(
                            path,
                            output_dir,
                            languages
                        )

                    else:

                        ocr_image(
                            path,
                            output,
                            languages
                        )

                        method = "OCR"

                    log_event(
                        db,
                        "INFO",
                        "OCR_COMPLETE",
                        "",
                        str(relative) + " | " + method
                    )

                    processed += 1

                except Exception as error:

                    failed += 1

                    log_event(
                        db,
                        "ERROR",
                        "OCR_ERROR",
                        "",
                        str(relative) + " | " + str(error)
                    )

    db.commit()

    say("OCR finished.")
    say("  Processed: " + str(processed))
    say("  Failed: " + str(failed))


# ============================================================
# TRANSLATION
# ============================================================

def split_text(text, limit=3500):

    chunks = []

    while len(text) > limit:

        position = text.rfind(
            "\n",
            0,
            limit
        )

        if position < limit // 2:
            position = limit

        chunks.append(
            text[:position]
        )

        text = text[position:]

    if text:
        chunks.append(text)

    return chunks


def run_translation(root, db, settings):

    say("\nARGOS TRANSLATION")

    try:

        import argostranslate.translate as argos_translate

    except ImportError:

        say("Argos Translate is not installed.")
        say("Install it separately and download the required language model.")
        return

    source_code = settings.get(
        "translation_from",
        "en"
    )

    target_code = settings.get(
        "translation_to",
        "ru"
    )

    languages = argos_translate.get_installed_languages()

    source_language = None
    target_language = None

    for language in languages:

        if language.code == source_code:
            source_language = language

        if language.code == target_code:
            target_language = language

    if not source_language or not target_language:

        say(
            "Required installed language models are missing: "
            + source_code + " -> " + target_code
        )

        say(
            "Install the Argos language package before translating."
        )

        return

    translation = source_language.get_translation(
        target_language
    )

    input_roots = [

        root / "05_DERIVED" / "OCR",

        root / "05_DERIVED" / "EXTRACTED_TEXT",

        root / "05_DERIVED" / "TRANSCRIPTS"

    ]

    output_root = (
        root / "05_DERIVED" / "TRANSLATIONS"
    )

    output_root.mkdir(
        parents=True,
        exist_ok=True
    )

    processed = 0
    failed = 0

    for input_root in input_roots:

        if not input_root.exists():
            continue

        for base, dirs, files in os.walk(input_root):

            for filename in files:

                if not filename.lower().endswith(".txt"):
                    continue

                source_path = Path(base) / filename

                relative = source_path.relative_to(
                    root / "05_DERIVED"
                )

                target_path = (
                    output_root /
                    relative.parent /
                    (source_path.stem + "." + target_code + ".txt")
                )

                if target_path.exists():
                    continue

                try:

                    text = source_path.read_text(
                        encoding="utf-8",
                        errors="replace"
                    )

                    translated = []

                    chunks = split_text(text)

                    for index, chunk in enumerate(chunks, 1):

                        translated.append(
                            translation.translate(chunk)
                        )

                        if index % 20 == 0:

                            say(
                                "  Chunks: %d / %d" %
                                (index, len(chunks))
                            )

                    target_path.parent.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                    target_path.write_text(
                        "\n".join(translated),
                        encoding="utf-8"
                    )

                    processed += 1

                except Exception as error:

                    failed += 1

                    log_event(
                        db,
                        "ERROR",
                        "TRANSLATION_ERROR",
                        "",
                        str(source_path) + " | " + str(error)
                    )

    db.commit()

    say("Translation finished.")
    say("  Processed: " + str(processed))
    say("  Failed: " + str(failed))


# ============================================================
# WHISPER TRANSCRIPTION
# ============================================================

def run_transcription(root, db, settings):

    say("\nWHISPER TRANSCRIPTION")

    whisper = shutil.which("whisper")

    if not whisper:

        say("Whisper CLI not installed.")
        say("Install Whisper and FFmpeg separately.")
        return

    model = settings.get(
        "whisper_model",
        "small"
    )

    processed = 0
    failed = 0

    for directory in DATA_DIRECTORIES:

        base_directory = root / directory

        if not base_directory.exists():
            continue

        for base, dirs, files in os.walk(base_directory):

            for filename in files:

                path = Path(base) / filename

                extension = path.suffix.lower()

                if extension not in MEDIA_EXTENSIONS:
                    continue

                # Image files are not audio/video.

                if extension in (
                    ".jpg", ".jpeg", ".png", ".gif",
                    ".tif", ".tiff", ".webp", ".bmp"
                ):
                    continue

                relative = path.relative_to(root)

                output_dir = (
                    root /
                    "05_DERIVED" /
                    "TRANSCRIPTS" /
                    relative.parent
                )

                output_dir.mkdir(
                    parents=True,
                    exist_ok=True
                )

                output_file = output_dir / (
                    path.stem + ".txt"
                )

                if output_file.exists():
                    continue

                say("  " + str(relative))

                try:

                    result = subprocess.run(
                        [
                            whisper,
                            str(path),
                            "--model",
                            model,
                            "--output_dir",
                            str(output_dir),
                            "--output_format",
                            "txt",
                            "--fp16",
                            "False"
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=None
                    )

                    if result.returncode == 0:

                        processed += 1

                    else:

                        failed += 1

                        log_event(
                            db,
                            "ERROR",
                            "WHISPER_ERROR",
                            "",
                            result.stdout[-3000:]
                        )

                except Exception as error:

                    failed += 1

                    log_event(
                        db,
                        "ERROR",
                        "WHISPER_ERROR",
                        "",
                        str(path) + " | " + str(error)
                    )

    db.commit()

    say("Transcription finished.")
    say("  Processed: " + str(processed))
    say("  Failed: " + str(failed))


# ============================================================
# FULL HEALTH CHECK
# ============================================================

def health_check(root, db, args):

    say("\nFULL HEALTH CHECK")

    disk_report(root)

    smart_report(
        root,
        args.device
    )

    quick_write_test(root)

    result = verify_local_files(
        db,
        root
    )

    say("\nHEALTH SUMMARY")

    for key, value in result.items():

        say(
            "  %-12s %d" %
            (key, value)
        )


# ============================================================
# FULL CYCLE
# ============================================================

def full_cycle(root, db, settings, args):

    say("\nFULL ARCHIVE CYCLE")

    health_check(
        root,
        db,
        args
    )

    discover_all(
        db,
        settings
    )

    probe_all(
        db,
        settings
    )

    export_manifests(
        db,
        root
    )

    show_status(db)

    count, size, unknown = download_estimate(
        db,
        root,
        settings
    )

    if count == 0:

        say("\nNothing pending.")
        return

    answer = input(
        "\nStart download? [y/N] "
    ).strip().lower()

    if answer not in ("y", "yes", "да", "д"):

        say("Download skipped.")

        verify_local_files(
            db,
            root
        )

        export_manifests(
            db,
            root
        )

        return

    download_pending(
        db,
        root,
        settings
    )

    inspect_archives(
        db,
        root
    )

    export_manifests(
        db,
        root
    )

    show_status(db)


# ============================================================
# CONTINUOUS MODE
# ============================================================

def continuous_mode(root, db, settings, args):

    interval = int(
        input(
            "Interval in minutes [1440]: "
        ).strip() or "1440"
    )

    say("\nCONTINUOUS MODE")

    say("Press Ctrl+C to stop.")

    while True:

        try:

            full_cycle(
                root,
                db,
                settings,
                args
            )

            say(
                "\nNext cycle in %d minutes." %
                interval
            )

            time.sleep(
                max(1, interval) * 60
            )

        except KeyboardInterrupt:

            say("\nContinuous mode stopped.")
            break


# ============================================================
# SETTINGS MENU
# ============================================================

def settings_menu(root, settings):

    while True:

        say("\nSETTINGS")

        print("1. Request delay")
        print("2. Retry count")
        print("3. Crawl depth")
        print("4. Page limit")
        print("5. Include media")
        print("6. Respect robots.txt")
        print("7. OCR languages")
        print("8. Translation source language")
        print("9. Translation target language")
        print("10. Whisper model")
        print("11. Internet Archive query")
        print("12. User-Agent")
        print("0. Back")

        choice = input("\nChoice: ").strip()

        if choice == "0":
            break

        elif choice == "1":

            value = input("Delay in seconds: ").strip()

            settings["delay"] = max(
                0.0,
                float(value)
            )

        elif choice == "2":

            settings["retries"] = max(
                1,
                int(input("Retries: "))
            )

        elif choice == "3":

            settings["crawl_depth"] = max(
                0,
                min(5, int(input("Depth: ")))
            )

        elif choice == "4":

            settings["page_limit"] = max(
                0,
                int(input("Page limit (0 = unlimited): "))
            )

        elif choice == "5":

            settings["include_media"] = (
                not settings["include_media"]
            )

        elif choice == "6":

            settings["respect_robots"] = (
                not settings["respect_robots"]
            )

        elif choice == "7":

            settings["ocr_languages"] = input(
                "Tesseract languages [eng+rus]: "
            ).strip() or "eng+rus"

        elif choice == "8":

            settings["translation_from"] = input(
                "Source language [en]: "
            ).strip() or "en"

        elif choice == "9":

            settings["translation_to"] = input(
                "Target language [ru]: "
            ).strip() or "ru"

        elif choice == "10":

            settings["whisper_model"] = input(
                "Whisper model [small]: "
            ).strip() or "small"

        elif choice == "11":

            settings["internet_archive_query"] = input(
                "Internet Archive query: "
            ).strip()

        elif choice == "12":

            settings["user_agent"] = input(
                "User-Agent: "
            ).strip() or USER_AGENT

        save_settings(
            root,
            settings
        )

        say("Settings saved.")


# ============================================================
# MENU
# ============================================================

def print_menu():

    print("""
==========================================================
             EPSTEIN PUBLIC RECORDS ARCHIVER
==========================================================

  1. Full cycle
  2. Discover sources and files
  3. Probe indexed URLs
  4. Calculate download estimate
  5. Download pending files
  6. Verify files and SHA-256
  7. Retry critical failures
  8. Inspect ZIP/TAR archives
  9. OCR PDFs and images
 10. Translate extracted text with Argos
 11. Transcribe audio/video with Whisper
 12. Full disk and archive health check
 13. Export manifests and reports
 14. Show archive status
 15. List source registry
 16. Add custom source
 17. Enable/disable source
 18. Settings
 19. Continuous mode

  0. Exit

==========================================================
""")


def menu(root, db, settings, args):

    while True:

        print_menu()

        choice = input("Command: ").strip()

        try:

            if choice == "0":

                say("Exiting.")
                break

            elif choice == "1":

                full_cycle(
                    root,
                    db,
                    settings,
                    args
                )

            elif choice == "2":

                discover_all(
                    db,
                    settings
                )

            elif choice == "3":

                probe_all(
                    db,
                    settings
                )

            elif choice == "4":

                download_estimate(
                    db,
                    root,
                    settings
                )

            elif choice == "5":

                count, total, unknown = download_estimate(
                    db,
                    root,
                    settings
                )

                if count:

                    answer = input(
                        "Start downloading? [y/N] "
                    ).strip().lower()

                    if answer in ("y", "yes", "да", "д"):

                        download_pending(
                            db,
                            root,
                            settings
                        )

            elif choice == "6":

                verify_local_files(
                    db,
                    root
                )

                rebaseline_file(
                    db,
                    root
                )

            elif choice == "7":

                retry_critical(
                    db,
                    root,
                    settings
                )

            elif choice == "8":

                inspect_archives(
                    db,
                    root
                )

            elif choice == "9":

                run_ocr(
                    root,
                    db,
                    settings
                )

            elif choice == "10":

                run_translation(
                    root,
                    db,
                    settings
                )

            elif choice == "11":

                run_transcription(
                    root,
                    db,
                    settings
                )

            elif choice == "12":

                health_check(
                    root,
                    db,
                    args
                )

            elif choice == "13":

                export_manifests(
                    db,
                    root
                )

            elif choice == "14":

                show_status(db)

            elif choice == "15":

                list_sources(db)

            elif choice == "16":

                add_custom_source(db)

            elif choice == "17":

                toggle_source(db)

            elif choice == "18":

                settings_menu(
                    root,
                    settings
                )

            elif choice == "19":

                continuous_mode(
                    root,
                    db,
                    settings,
                    args
                )

            else:

                say("Unknown command.")

        except KeyboardInterrupt:

            say("\nOperation interrupted.")
            say("Current partial downloads are retained.")

        except Exception as error:

            say("\nOperation failed:")
            say(str(error))

            log_event(
                db,
                "ERROR",
                "MENU_OPERATION_ERROR",
                "",
                str(error)
            )

        pause()


# ============================================================
# COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=APP_NAME
    )

    parser.add_argument(
        "--root",
        help="Archive directory"
    )

    parser.add_argument(
        "--device",
        help="Disk device for SMART check"
    )

    parser.add_argument(
        "--discover",
        action="store_true"
    )

    parser.add_argument(
        "--verify",
        action="store_true"
    )

    parser.add_argument(
        "--full",
        action="store_true"
    )

    parser.add_argument(
        "--include-media",
        action="store_true"
    )

    parser.add_argument(
        "--no-menu",
        action="store_true"
    )

    args = parser.parse_args()

    say(APP_NAME + " v" + VERSION)

    say("Python: " + platform.python_version())

    say("One download at a time.")
    say("Streaming downloads.")
    say("No configured maximum file size.")
    say("No automatic filesystem repair.")

    root_value = args.root

    if not root_value:

        root_value = input(
            "\nArchive directory "
            "[./EPSTEIN_ARCHIVE]: "
        ).strip()

    if not root_value:
        root_value = "./EPSTEIN_ARCHIVE"

    root = Path(
        root_value
    ).expanduser().resolve()

    if not root.exists():

        answer = input(
            "\nDirectory does not exist:\n"
            + str(root) +
            "\nCreate it? [Y/n] "
        ).strip().lower()

        if answer in ("n", "no", "нет", "н"):

            say("Stopped.")
            return

    initialize(root)

    say("\nArchive directory:")
    say(str(root))

    disk_report(root)

    settings = get_settings(root)

    if args.include_media:
        settings["include_media"] = True

    db = open_database(root)

    if args.verify:

        verify_local_files(
            db,
            root
        )

        export_manifests(
            db,
            root
        )

    elif args.discover:

        discover_all(
            db,
            settings
        )

        probe_all(
            db,
            settings
        )

        export_manifests(
            db,
            root
        )

    elif args.full:

        full_cycle(
            root,
            db,
            settings,
            args
        )

    elif args.no_menu:

        full_cycle(
            root,
            db,
            settings,
            args
        )

    else:

        menu(
            root,
            db,
            settings,
            args
        )

    db.close()

    say("\nARCHIVER FINISHED")


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        say("\nStopped by user.")
        say("Partial downloads are preserved.")
        sys.exit(130)

    except Exception as error:

        say("\nFATAL ERROR")
        say(str(error))
        sys.exit(1)

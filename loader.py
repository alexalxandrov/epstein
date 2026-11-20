
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EPSTEIN ARCHIVE
Local-first public-record collection and verification tool.

Python 3.9+
Standard library only.

Features:
- Source registry
- Source availability checks
- HTML discovery crawler
- Candidate URL preflight
- SQLite inventory
- SHA-256 verification
- Duplicate detection
- Resumable downloads
- Retry failed URLs
- Disk space checks
- Read-only SMART checks (optional)
- Monitoring mode

The program does not download suspected illegal intimate material,
CSAM, or other material marked for manual review.
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import shutil
import hashlib
import sqlite3
import logging
import mimetypes
import subprocess
import urllib.request
import urllib.error

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import (
    urljoin,
    urlparse,
    unquote,
    urldefrag,
)
from html.parser import HTMLParser
from email.message import Message


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "EPSTEIN ARCHIVE"
VERSION = "1.0.0"

DEFAULT_ARCHIVE = Path.home() / "EPSTEIN_ARCHIVE"

DATABASE_NAME = "archive.sqlite"
USER_AGENT = "EpsteinArchiveResearchTool/1.0"

REQUEST_TIMEOUT = 25
DOWNLOAD_TIMEOUT = 90

CRAWL_DEPTH = 2
CRAWL_PAGE_LIMIT = 250

CRAWL_DELAY = 0.4
DOWNLOAD_DELAY = 0.3

MONITOR_INTERVAL_HOURS = 6

CHUNK_SIZE = 1024 * 1024
HTML_READ_LIMIT = 5 * 1024 * 1024

RETRY_ATTEMPTS = 3
RETRY_DELAY = 3

# Never automatically download URLs that appear to point to
# potentially illegal intimate material or sensitive personal data.
MANUAL_REVIEW_PATTERNS = [
    r"child[-_ ]?porn",
    r"child[-_ ]?sexual",
    r"csam",
    r"sexual[-_ ]?abuse[-_ ]?images",
    r"nonconsensual[-_ ]?intimate",
    r"revenge[-_ ]?porn",
]

# URL patterns that are usually not downloadable documents.
IGNORE_EXTENSIONS = {
    ".css", ".js", ".map",
    ".woff", ".woff2", ".ttf",
    ".eot", ".ico",
    ".svg",
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".csv",
    ".txt", ".rtf", ".odt",
    ".ods", ".ppt", ".pptx",
    ".zip", ".7z", ".rar",
    ".tar", ".gz", ".bz2",
    ".json", ".xml",
    ".jpg", ".jpeg", ".png",
    ".tif", ".tiff",
    ".mp3", ".wav", ".mp4",
    ".mov", ".m4v", ".webm",
}


# ============================================================
# SOURCES
# ============================================================

# type:
#   official
#   court
#   government
#   archive
#   secondary
#   community
#
# trust:
#   primary
#   institutional
#   secondary
#   community
#
# auto_download=False means that discovery is allowed,
# but automatic downloading is disabled.

SOURCES = [

    # --------------------------------------------------------
    # US DEPARTMENT OF JUSTICE
    # --------------------------------------------------------

    {
        "name": "DOJ Epstein Library",
        "url": "https://www.justice.gov/epstein",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "DOJ Epstein Disclosures",
        "url": "https://www.justice.gov/epstein/doj-disclosures",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "DOJ OIG",
        "url": "https://oig.justice.gov/reports",
        "type": "government",
        "trust": "institutional",
        "auto_download": True,
    },
    {
        "name": "DOJ OPR Epstein Report",
        "url": "https://www.justice.gov/archives/opa/pr/statement-doj-office-professional-responsibility-report-jeffrey-epstein-2006-2008",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "DOJ OIP Documents",
        "url": "https://www.justice.gov/oip/available-documents-oip",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },

    # --------------------------------------------------------
    # FBI
    # --------------------------------------------------------

    {
        "name": "FBI Vault Jeffrey Epstein",
        "url": "https://vault.fbi.gov/jeffrey-epstein/",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "FBI Investigative Holdings Review",
        "url": "https://vault.fbi.gov/records-regarding-the-review-of-the-investigative-holdings-related-to-jeffrey-epstein/records-regarding-the-review-of-the-investigative-holdings-related-to-jeffrey-epstein",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },

    # --------------------------------------------------------
    # US CONGRESS
    # --------------------------------------------------------

    {
        "name": "House Oversight DOJ Production",
        "url": "https://oversight.house.gov/release/oversight-committee-releases-epstein-records-provided-by-the-department-of-justice/",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "House Oversight Estate Production",
        "url": "https://oversight.house.gov/release/oversight-committee-releases-additional-epstein-estate-documents/",
        "type": "official",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "House DOJ Google Drive",
        "url": "https://drive.google.com/drive/folders/1TrGxDGQLDLZu1vvvZDBAh-e7wN3y6Hoz?usp=sharing",
        "type": "official",
        "trust": "primary",
        "auto_download": False,
    },
    {
        "name": "House Estate Google Drive",
        "url": "https://drive.google.com/drive/folders/1hTNH5woIRio578onLGElkTWofUSWRoH_?usp=sharing",
        "type": "official",
        "trust": "primary",
        "auto_download": False,
    },
    {
        "name": "House DOJ Dropbox",
        "url": "https://www.dropbox.com/scl/fo/98fthv8otekjk28lcrnc5/AIn3egnE58MYe4Bn4fliVBw?dl=0&rlkey=m7p8e9omml96fgxl13kr2nuyt&st=0xvm0p08",
        "type": "official",
        "trust": "primary",
        "auto_download": False,
    },
    {
        "name": "House Estate Dropbox",
        "url": "https://www.dropbox.com/scl/fo/9bq6uj0pnycpa4gxqiuzs/ABBA-BoYUAT7627MBeLiVYg?rlkey=3s6ggcjihou9nt8srsn2qt1n7&st=4aejaath&dl=0",
        "type": "official",
        "trust": "primary",
        "auto_download": False,
    },

    # --------------------------------------------------------
    # COURTS AND LEGAL RECORDS
    # --------------------------------------------------------

    {
        "name": "PACER",
        "url": "https://pacer.uscourts.gov/",
        "type": "court",
        "trust": "primary",
        "auto_download": False,
    },
    {
        "name": "CourtListener",
        "url": "https://www.courtlistener.com/",
        "type": "court",
        "trust": "institutional",
        "auto_download": True,
    },
    {
        "name": "CourtListener RECAP",
        "url": "https://www.courtlistener.com/recap/",
        "type": "court",
        "trust": "institutional",
        "auto_download": True,
    },
    {
        "name": "USVI Recorder of Deeds",
        "url": "https://usvi.publicsearch.us/",
        "type": "government",
        "trust": "primary",
        "auto_download": False,
    },
    {
        "name": "Florida State Attorney 15th Judicial Circuit",
        "url": "https://sa15.org/public-records/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },

    # --------------------------------------------------------
    # OTHER GOVERNMENT SOURCES
    # --------------------------------------------------------

    {
        "name": "CBP Epstein FOIA Records",
        "url": "https://www.cbp.gov/document/foia-record/jeffrey-epstein-records",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "GovInfo",
        "url": "https://www.govinfo.gov/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "Congress.gov",
        "url": "https://www.congress.gov/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "Senate Finance",
        "url": "https://www.finance.senate.gov/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "Wyden Epstein Report",
        "url": "https://www.finance.senate.gov/ranking-members-news/wyden-releases-new-report-on-failure-of-wall-street-banks-to-blow-the-whistle-on-jeffrey-epsteins-sex-trafficking-and-money-laundering-schemes",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "National Archives",
        "url": "https://www.archives.gov/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "ICE FOIA",
        "url": "https://www.ice.gov/foia",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "State Department FOIA",
        "url": "https://foia.state.gov/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "Treasury FOIA",
        "url": "https://home.treasury.gov/footer/freedom-of-information-act",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },

    # --------------------------------------------------------
    # FINANCIAL AND CORPORATE DATA
    # --------------------------------------------------------

    {
        "name": "SEC EDGAR",
        "url": "https://www.sec.gov/edgar/search/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "FEC",
        "url": "https://www.fec.gov/data/",
        "type": "government",
        "trust": "primary",
        "auto_download": True,
    },
    {
        "name": "ICIJ Offshore Leaks",
        "url": "https://offshoreleaks.icij.org/",
        "type": "archive",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "OpenCorporates",
        "url": "https://opencorporates.com/",
        "type": "archive",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "ProPublica Nonprofit Explorer",
        "url": "https://projects.propublica.org/nonprofits/",
        "type": "archive",
        "trust": "secondary",
        "auto_download": True,
    },

    # --------------------------------------------------------
    # DOCUMENT ARCHIVES
    # --------------------------------------------------------

    {
        "name": "DocumentCloud",
        "url": "https://www.documentcloud.org/",
        "type": "archive",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "MuckRock",
        "url": "https://www.muckrock.com/",
        "type": "archive",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Internet Archive",
        "url": "https://archive.org/",
        "type": "archive",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Google Pinpoint",
        "url": "https://journaliststudio.google.com/pinpoint/search?collection=092314e384a58618",
        "type": "archive",
        "trust": "secondary",
        "auto_download": False,
    },

    # --------------------------------------------------------
    # SECONDARY RESEARCH PROJECTS
    # --------------------------------------------------------

    {
        "name": "Epstein Files GitHub Index",
        "url": "https://github.com/yung-megafone/Epstein-Files",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "EpsteinScan",
        "url": "https://www.epsteinscan.org/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Exposed",
        "url": "https://epsteinexposed.com/resources",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Project",
        "url": "https://epsteinproject.org/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Suite",
        "url": "https://epsteinsuite.com/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Graph",
        "url": "https://epsteingraph.com/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Observer",
        "url": "https://epstein.observer/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Track the Files",
        "url": "https://trackthefiles.org/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Unboxed",
        "url": "https://www.epsteinunboxed.com/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Search Epstein Files",
        "url": "https://searchepsteinfiles.com/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Filez",
        "url": "https://epsteinfilez.com/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Epstein Forums",
        "url": "https://epsteinforums.org/",
        "type": "community",
        "trust": "community",
        "auto_download": True,
    },
    {
        "name": "JEEScholar",
        "url": "https://jeescholar.com/",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },
    {
        "name": "Money Network",
        "url": "https://tommycarstensen.com/epstein/money_network.html",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": True,
    },

    # --------------------------------------------------------
    # JMAIL
    # --------------------------------------------------------

    {
        "name": "Jmail About",
        "url": "https://jmail.world/about",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": False,
    },
    {
        "name": "Jmail Photos",
        "url": "https://jmail.world/photos",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": False,
    },
    {
        "name": "Jmail Videos",
        "url": "https://jmail.world/jefftube",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": False,
    },
    {
        "name": "Jmail Flights",
        "url": "https://jmail.world/flights",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": False,
    },
    {
        "name": "Jmail Taxonomy",
        "url": "https://jmail.world/taxonomy",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": False,
    },
    {
        "name": "Jmail Wiki",
        "url": "https://jmail.world/wiki",
        "type": "secondary",
        "trust": "secondary",
        "auto_download": False,
    },

    # --------------------------------------------------------
    # COMMUNITY
    # --------------------------------------------------------

    {
        "name": "Reddit Research Tools Megathread",
        "url": "https://www.reddit.com/r/Epstein/comments/1rc3gaz/megathread_list_of_research_tools_and_websites/",
        "type": "community",
        "trust": "community",
        "auto_download": False,
    },
    {
        "name": "Reddit Research Tools Megathread Part 2",
        "url": "https://www.reddit.com/r/Epstein/comments/1wwsfs8/megathread_list_of_research_tools_and_websites/",
        "type": "community",
        "trust": "community",
        "auto_download": False,
    },
]


# ============================================================
# LOGGING
# ============================================================

def setup_logging(root: Path):
    log_dir = root / "09_LOGS"
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / "archive.log"

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def log(level, message):
    getattr(logging, level.lower())(message)


# ============================================================
# TERMINAL UI
# ============================================================

def banner():
    print()
    print("=" * 72)
    print("  EPSTEIN ARCHIVE :: PUBLIC RECORD COLLECTION SYSTEM")
    print("  Version:", VERSION)
    print("=" * 72)
    print()


def pause():
    input("\nPress ENTER to continue...")


def ask_yes_no(question, default=False):
    suffix = "[Y/n]" if default else "[y/N]"

    answer = input(f"{question} {suffix}: ").strip().lower()

    if not answer:
        return default

    return answer in ("y", "yes", "д", "да")


def menu():
    print()
    print("  [1] Discovery + preflight + download")
    print("  [2] Verify existing archive")
    print("  [3] Show archive status")
    print("  [4] Retry failed URLs")
    print("  [5] Run monitoring mode")
    print("  [6] Check disk / SMART")
    print("  [7] Export manifests")
    print("  [0] Exit")
    print()


# ============================================================
# FILESYSTEM LAYOUT
# ============================================================

DIRECTORIES = [
    "00_ADMIN",
    "01_RAW_OFFICIAL",
    "02_MEDIA_ARCHIVES",
    "03_SECONDARY_ARCHIVES",
    "04_COMMUNITY_RESEARCH",
    "05_DERIVED/OCR",
    "05_DERIVED/EXTRACTED_TEXT",
    "05_DERIVED/TRANSCRIPTS",
    "05_DERIVED/METADATA",
    "06_DATABASE",
    "07_MANIFESTS",
    "08_MONITORING",
    "09_LOGS",
    "99_STAGING/DISCOVERED",
    "99_STAGING/DOWNLOADING",
    "99_STAGING/QUARANTINE",
]


def initialize_layout(root: Path):
    for item in DIRECTORIES:
        (root / item).mkdir(parents=True, exist_ok=True)


def choose_root():
    print("Archive directory:")
    print("Default:", DEFAULT_ARCHIVE)

    raw = input("Path [ENTER = default]: ").strip()

    root = Path(raw).expanduser() if raw else DEFAULT_ARCHIVE

    if not root.exists():
        if ask_yes_no(f"Directory does not exist. Create {root}?", True):
            root.mkdir(parents=True, exist_ok=True)
        else:
            raise SystemExit("Archive directory was not created.")

    if not root.is_dir():
        raise SystemExit("Selected path is not a directory.")

    return root.resolve()


# ============================================================
# DATABASE
# ============================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    source_type TEXT,
    trust_level TEXT,
    auto_download INTEGER DEFAULT 1,
    status INTEGER,
    last_checked TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    source_id INTEGER,
    discovered_from TEXT,
    depth INTEGER DEFAULT 0,
    status INTEGER,
    content_type TEXT,
    expected_size INTEGER,
    filename TEXT,
    last_checked TEXT,
    error TEXT,
    manual_review INTEGER DEFAULT 0,
    excluded_reason TEXT,
    download_enabled INTEGER DEFAULT 1,
    FOREIGN KEY(source_id) REFERENCES sources(id)
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id INTEGER,
    source_id INTEGER,
    url TEXT,
    path TEXT UNIQUE NOT NULL,
    filename TEXT,
    size INTEGER,
    sha256 TEXT,
    etag TEXT,
    last_modified TEXT,
    downloaded_at TEXT,
    verification_status TEXT,
    duplicate_group TEXT,
    FOREIGN KEY(candidate_id) REFERENCES candidates(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    level TEXT,
    event_type TEXT,
    url TEXT,
    message TEXT
);

CREATE TABLE IF NOT EXISTS crawl_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    source_id INTEGER,
    status INTEGER,
    crawled_at TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_candidates_status
ON candidates(status);

CREATE INDEX IF NOT EXISTS idx_files_hash
ON files(sha256);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON events(timestamp);
"""


def connect_db(root: Path):
    db_path = root / "06_DATABASE" / DATABASE_NAME

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript(SCHEMA)
    conn.commit()

    return conn


def event(db, level, event_type, message, url=None):
    db.execute(
        """
        INSERT INTO events
        (timestamp, level, event_type, url, message)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            utc_now(),
            level,
            event_type,
            url,
            message,
        ),
    )
    db.commit()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# SOURCE REGISTRY
# ============================================================

def register_sources(db):
    for source in SOURCES:
        db.execute(
            """
            INSERT INTO sources
            (name, url, source_type, trust_level, auto_download)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                url=excluded.url,
                source_type=excluded.source_type,
                trust_level=excluded.trust_level,
                auto_download=excluded.auto_download
            """,
            (
                source["name"],
                source["url"],
                source["type"],
                source["trust"],
                int(source.get("auto_download", True)),
            ),
        )

    db.commit()


def get_source_id(db, name):
    row = db.execute(
        "SELECT id FROM sources WHERE name=?",
        (name,),
    ).fetchone()

    return row["id"] if row else None


# ============================================================
# HTTP
# ============================================================

def make_request(url, method="GET", headers=None):
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }

    if headers:
        request_headers.update(headers)

    req = urllib.request.Request(
        url,
        headers=request_headers,
        method=method,
    )

    return urllib.request.urlopen(
        req,
        timeout=REQUEST_TIMEOUT,
    )


def probe_url(url):
    """
    Return:
        status, content_type, content_length, final_url, error
    """

    try:
        response = make_request(url, "HEAD")

        status = response.getcode()
        headers = response.headers
        final_url = response.geturl()

        content_type = headers.get("Content-Type")
        content_length = headers.get("Content-Length")

        size = None

        if content_length and content_length.isdigit():
            size = int(content_length)

        response.close()

        return status, content_type, size, final_url, None

    except urllib.error.HTTPError as exc:
        status = exc.code

        if status not in (405, 501):
            return status, None, None, url, str(exc)

    except Exception as exc:
        log("debug", f"HEAD failed: {url}: {exc}")

    # Fallback to Range GET.

    try:
        response = make_request(
            url,
            "GET",
            {"Range": "bytes=0-0"},
        )

        status = response.getcode()
        headers = response.headers

        content_type = headers.get("Content-Type")
        content_length = headers.get("Content-Length")

        size = None

        content_range = headers.get("Content-Range")

        if content_range:
            match = re.search(r"/(\d+)$", content_range)

            if match:
                size = int(match.group(1))

        elif content_length and content_length.isdigit():
            size = int(content_length)

        final_url = response.geturl()

        response.close()

        return status, content_type, size, final_url, None

    except urllib.error.HTTPError as exc:
        return exc.code, None, None, url, str(exc)

    except Exception as exc:
        return None, None, None, url, str(exc)


def is_success(status):
    return status is not None and 200 <= status < 400


# ============================================================
# SOURCE AVAILABILITY CHECK
# ============================================================

def probe_sources(db):
    print("\n[PHASE 1] SOURCE AVAILABILITY CHECK\n")

    rows = db.execute(
        "SELECT * FROM sources ORDER BY id"
    ).fetchall()

    for row in rows:
        url = row["url"]

        log("info", f"Checking source: {row['name']}")

        status, ctype, size, final_url, error = probe_url(url)

        db.execute(
            """
            UPDATE sources
            SET status=?, last_checked=?, error=?
            WHERE id=?
            """,
            (
                status,
                utc_now(),
                error,
                row["id"],
            ),
        )

        if is_success(status):
            log("info", f"AVAILABLE [{status}] {row['name']}")
        else:
            log(
                "warning",
                f"UNAVAILABLE [{status}] {row['name']} :: {error}",
            )

        event(
            db,
            "INFO" if is_success(status) else "WARN",
            "SOURCE_PROBE",
            f"HTTP {status}; {error or 'OK'}",
            url,
        )

        db.commit()
        time.sleep(CRAWL_DELAY)


# ============================================================
# HTML LINK EXTRACTION
# ============================================================

class LinkParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        for key in ("href", "src", "data-href"):
            value = attrs.get(key)

            if value:
                self.links.append(value)


def extract_links(html, base_url):
    parser = LinkParser()

    try:
        parser.feed(html)
    except Exception:
        pass

    result = []

    for link in parser.links:
        absolute = urljoin(base_url, link)
        absolute, _ = urldefrag(absolute)

        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https"):
            continue

        result.append(absolute)

    return list(dict.fromkeys(result))


# ============================================================
# URL CLASSIFICATION
# ============================================================

def is_manual_review_url(url):
    text = unquote(url).lower()

    for pattern in MANUAL_REVIEW_PATTERNS:
        if re.search(pattern, text, re.I):
            return True

    return False


def extension_of(url):
    path = unquote(urlparse(url).path)
    return Path(path).suffix.lower()


def looks_like_document(url, content_type=None):
    ext = extension_of(url)

    if ext in IGNORE_EXTENSIONS:
        return False

    if ext in DOCUMENT_EXTENSIONS:
        return True

    if content_type:
        ctype = content_type.lower()

        if any(x in ctype for x in (
            "pdf",
            "msword",
            "officedocument",
            "spreadsheet",
            "presentation",
            "octet-stream",
            "text/plain",
            "text/csv",
            "image/",
            "video/",
            "audio/",
            "application/zip",
        )):
            return True

    return False


def filename_from_url(url):
    name = Path(unquote(urlparse(url).path)).name

    if not name:
        name = "download"

    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name)

    return name[:180]


def safe_filename(name):
    name = unquote(name or "download")

    name = name.replace("/", "_")
    name = name.replace("\\", "_")

    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name)

    return name[:180] or "download"


def candidate_directory(source_type):
    mapping = {
        "official": "01_RAW_OFFICIAL",
        "court": "01_RAW_OFFICIAL/FEDERAL_COURTS",
        "government": "01_RAW_OFFICIAL/FOIA_EXTERNAL",
        "archive": "03_SECONDARY_ARCHIVES",
        "secondary": "03_SECONDARY_ARCHIVES",
        "community": "04_COMMUNITY_RESEARCH",
    }

    return mapping.get(source_type, "99_STAGING/DISCOVERED")


# ============================================================
# CANDIDATE REGISTRATION
# ============================================================

def add_candidate(
    db,
    url,
    source_id,
    discovered_from,
    depth,
    download_enabled=True,
):
    if not url.startswith(("http://", "https://")):
        return

    manual = is_manual_review_url(url)

    if manual:
        download_enabled = False

    db.execute(
        """
        INSERT INTO candidates
        (
            url,
            source_id,
            discovered_from,
            depth,
            manual_review,
            download_enabled,
            excluded_reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET
            discovered_from=COALESCE(
                candidates.discovered_from,
                excluded.discovered_from
            )
        """,
        (
            url,
            source_id,
            discovered_from,
            depth,
            int(manual),
            int(download_enabled),
            "Potentially sensitive URL; manual review required"
            if manual else None,
        ),
    )

    db.commit()


# ============================================================
# CRAWLER
# ============================================================

def fetch_html(url):
    try:
        response = make_request(url, "GET")

        status = response.getcode()
        content_type = response.headers.get("Content-Type", "")

        if "html" not in content_type.lower():
            response.close()
            return status, None, content_type, response.geturl()

        data = response.read(HTML_READ_LIMIT + 1)
        response.close()

        if len(data) > HTML_READ_LIMIT:
            data = data[:HTML_READ_LIMIT]

        encoding = "utf-8"

        charset_match = re.search(
            r"charset=([A-Za-z0-9_-]+)",
            content_type,
            re.I,
        )

        if charset_match:
            encoding = charset_match.group(1)

        try:
            html = data.decode(encoding, errors="replace")
        except LookupError:
            html = data.decode("utf-8", errors="replace")

        return status, html, content_type, response.geturl()

    except urllib.error.HTTPError as exc:
        return exc.code, None, None, url

    except Exception as exc:
        log("warning", f"HTML fetch failed: {url}: {exc}")
        return None, None, None, url


def crawl_source(db, source, source_id):
    print(f"\n[CRAWL] {source['name']}")

    start_url = source["url"]

    queue = [(start_url, 0)]
    visited = set()

    allowed_hosts = {
        urlparse(start_url).netloc.lower()
    }

    page_count = 0

    while queue and page_count < CRAWL_PAGE_LIMIT:

        url, depth = queue.pop(0)

        if url in visited:
            continue

        visited.add(url)

        if depth > CRAWL_DEPTH:
            continue

        page_count += 1

        log("debug", f"CRAWL {depth}: {url}")

        status, html, ctype, final_url = fetch_html(url)

        db.execute(
            """
            INSERT INTO crawl_pages
            (url, source_id, status, crawled_at, error)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                status=excluded.status,
                crawled_at=excluded.crawled_at,
                error=excluded.error
            """,
            (
                url,
                source_id,
                status,
                utc_now(),
                None if html is not None else "Page unavailable or non-HTML",
            ),
        )

        db.commit()

        if not html:
            continue

        links = extract_links(html, final_url)

        for link in links:

            parsed = urlparse(link)
            host = parsed.netloc.lower()

            ext = extension_of(link)

            if ext in IGNORE_EXTENSIONS:
                continue

            manual = is_manual_review_url(link)

            if looks_like_document(link):
                add_candidate(
                    db,
                    link,
                    source_id,
                    url,
                    depth + 1,
                    source.get("auto_download", True) and not manual,
                )

            # Follow same-host links.
            # Known document-storage hosts are allowed as external
            # discoveries, but are not recursively crawled.

            if host in allowed_hosts and depth < CRAWL_DEPTH:
                if link not in visited:
                    queue.append((link, depth + 1))

        time.sleep(CRAWL_DELAY)

    log(
        "info",
        f"Finished {source['name']}: {page_count} pages visited",
    )


def discover_all(db):
    print("\n[PHASE 2] DEEP DISCOVERY\n")

    sources = db.execute(
        "SELECT * FROM sources ORDER BY id"
    ).fetchall()

    for row in sources:
        source = {
            "name": row["name"],
            "url": row["url"],
            "auto_download": bool(row["auto_download"]),
        }

        try:
            crawl_source(
                db,
                source,
                row["id"],
            )

        except KeyboardInterrupt:
            raise

        except Exception as exc:
            log(
                "error",
                f"Source crawler failed: {row['name']}: {exc}",
            )

            event(
                db,
                "ERROR",
                "CRAWLER_FAILURE",
                str(exc),
                row["url"],
            )


# ============================================================
# CANDIDATE PREFLIGHT
# ============================================================

def probe_candidates(db):
    print("\n[PHASE 3] INDIVIDUAL URL PREFLIGHT\n")

    rows = db.execute(
        """
        SELECT *
        FROM candidates
        ORDER BY id
        """
    ).fetchall()

    total = len(rows)

    print("Candidates:", total)

    for index, row in enumerate(rows, 1):

        url = row["url"]

        log(
            "info",
            f"[{index}/{total}] Checking {url}",
        )

        status, ctype, size, final_url, error = probe_url(url)

        db.execute(
            """
            UPDATE candidates
            SET status=?,
                content_type=?,
                expected_size=?,
                last_checked=?,
                error=?
            WHERE id=?
            """,
            (
                status,
                ctype,
                size,
                utc_now(),
                error,
                row["id"],
            ),
        )

        db.commit()

        if is_success(status):
            log(
                "info",
                f"AVAILABLE [{status}] size={size} type={ctype}",
            )
        else:
            log(
                "warning",
                f"FAILED [{status}] {error or ''}",
            )

        event(
            db,
            "INFO" if is_success(status) else "WARN",
            "CANDIDATE_PREFLIGHT",
            f"HTTP={status}; size={size}; type={ctype}; error={error}",
            url,
        )

        time.sleep(CRAWL_DELAY)

    failed = db.execute(
        """
        SELECT *
        FROM candidates
        WHERE status IS NULL OR status < 200 OR status >= 400
        ORDER BY status, url
        """
    ).fetchall()

    print("\nFAILED / UNAVAILABLE URLS:", len(failed))

    for row in failed:
        print(
            f"  [{row['status']}] {row['url']}"
        )

    if failed and ask_yes_no(
        "Retry failed URL checks now?",
        False,
    ):
        retry_candidate_probes(db, failed)


def retry_candidate_probes(db, rows):
    print("\n[RETRY] Failed URL checks\n")

    for row in rows:

        status = None
        ctype = None
        size = None
        error = None

        for attempt in range(1, RETRY_ATTEMPTS + 1):

            log(
                "info",
                f"Retry {attempt}/{RETRY_ATTEMPTS}: {row['url']}",
            )

            status, ctype, size, final_url, error = probe_url(
                row["url"]
            )

            if is_success(status):
                break

            time.sleep(RETRY_DELAY * attempt)

        db.execute(
            """
            UPDATE candidates
            SET status=?,
                content_type=?,
                expected_size=?,
                last_checked=?,
                error=?
            WHERE id=?
            """,
            (
                status,
                ctype,
                size,
                utc_now(),
                error,
                row["id"],
            ),
        )

        db.commit()


# ============================================================
# DISK CHECKS
# ============================================================

def disk_status(root: Path):
    usage = shutil.disk_usage(root)

    print("\nDISK STATUS")
    print("-" * 50)
    print("Total:     ", format_bytes(usage.total))
    print("Used:      ", format_bytes(usage.used))
    print("Free:      ", format_bytes(usage.free))

    return usage


def format_bytes(value):
    if value is None:
        return "UNKNOWN"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]

    value = float(value)

    for unit in units:
        if value < 1024:
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} EB"


def check_smart():
    print("\nSMART CHECK")

    executable = shutil.which("smartctl")

    if not executable:
        print("smartctl not installed; SMART check skipped.")
        return

    try:
        scan = subprocess.run(
            [executable, "--scan"],
            capture_output=True,
            text=True,
            timeout=20,
        )

        devices = []

        for line in scan.stdout.splitlines():
            match = re.match(r"^(/dev/\S+)", line)

            if match:
                devices.append(match.group(1))

        if not devices:
            print("No SMART devices detected.")
            return

        for device in devices:
            print("\nDevice:", device)

            result = subprocess.run(
                [
                    executable,
                    "-H",
                    device,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            print(result.stdout or result.stderr)

    except Exception as exc:
        log("warning", f"SMART check failed: {exc}")


# ============================================================
# DOWNLOAD ESTIMATION
# ============================================================

def estimate_download(db):
    row = db.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(expected_size) AS known_size,
            SUM(CASE WHEN expected_size IS NULL THEN 1 ELSE 0 END)
                AS unknown_size
        FROM candidates
        WHERE status >= 200
          AND status < 400
          AND download_enabled=1
          AND manual_review=0
        """
    ).fetchone()

    known_size = row["known_size"] or 0

    print("\nDOWNLOAD ESTIMATE")
    print("-" * 50)
    print("Available candidates:", row["total"])
    print("Known total size:    ", format_bytes(known_size))
    print("Unknown-size URLs:   ", row["unknown_size"])

    return known_size, row["unknown_size"]


def candidates_for_download(db):
    return db.execute(
        """
        SELECT c.*, s.name AS source_name,
               s.source_type AS source_type,
               s.trust_level AS trust_level
        FROM candidates c
        LEFT JOIN sources s ON s.id=c.source_id
        WHERE c.status >= 200
          AND c.status < 400
          AND c.download_enabled=1
          AND c.manual_review=0
          AND c.excluded_reason IS NULL
        ORDER BY
            CASE s.trust_level
                WHEN 'primary' THEN 1
                WHEN 'institutional' THEN 2
                WHEN 'secondary' THEN 3
                ELSE 4
            END,
            c.id
        """
    ).fetchall()


# ============================================================
# HASHING AND LOCAL INVENTORY
# ============================================================

def sha256_file(path: Path):
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK_SIZE)

            if not block:
                break

            digest.update(block)

    return digest.hexdigest()


def inventory(root: Path, db):
    print("\n[INVENTORY] Scanning selected archive directory")

    count = 0

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        if path.name.endswith(".part"):
            continue

        if path.name == DATABASE_NAME:
            continue

        try:
            relative = str(path.relative_to(root))
            stat = path.stat()
            digest = sha256_file(path)

            row = db.execute(
                """
                SELECT id, size, sha256
                FROM files
                WHERE path=?
                """,
                (relative,),
            ).fetchone()

            if row:
                db.execute(
                    """
                    UPDATE files
                    SET size=?,
                        sha256=?,
                        verification_status=?,
                        downloaded_at=COALESCE(downloaded_at, ?)
                    WHERE id=?
                    """,
                    (
                        stat.st_size,
                        digest,
                        "INVENTORIED",
                        utc_now(),
                        row["id"],
                    ),
                )
            else:
                db.execute(
                    """
                    INSERT INTO files
                    (
                        path,
                        filename,
                        size,
                        sha256,
                        downloaded_at,
                        verification_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        relative,
                        path.name,
                        stat.st_size,
                        digest,
                        utc_now(),
                        "INVENTORIED",
                    ),
                )

            count += 1

            if count % 25 == 0:
                db.commit()
                log("info", f"Inventoried {count} files")

        except Exception as exc:
            log("error", f"Inventory failed: {path}: {exc}")

    db.commit()

    print("Files inventoried:", count)


def verify_inventory(root: Path, db):
    print("\n[VERIFY] Existing archive")

    rows = db.execute(
        "SELECT * FROM files ORDER BY path"
    ).fetchall()

    missing = 0
    changed = 0
    verified = 0
    duplicates = 0

    hash_groups = {}

    for row in rows:

        path = root / row["path"]

        if not path.exists():
            missing += 1

            db.execute(
                """
                UPDATE files
                SET verification_status='MISSING'
                WHERE id=?
                """,
                (row["id"],),
            )

            log("warning", f"MISSING: {row['path']}")
            continue

        try:
            actual_size = path.stat().st_size
            actual_hash = sha256_file(path)

            if (
                actual_size != row["size"]
                or actual_hash != row["sha256"]
            ):
                changed += 1

                db.execute(
                    """
                    UPDATE files
                    SET verification_status='CHANGED'
                    WHERE id=?
                    """,
                    (row["id"],),
                )

                log("warning", f"CHANGED: {row['path']}")

            else:
                verified += 1

                db.execute(
                    """
                    UPDATE files
                    SET verification_status='VERIFIED'
                    WHERE id=?
                    """,
                    (row["id"],),
                )

            if actual_hash:
                hash_groups.setdefault(actual_hash, []).append(row["id"])

        except Exception as exc:
            log("error", f"Verify failed: {path}: {exc}")

    # Duplicate detection does not delete files.
    for digest, ids in hash_groups.items():

        if len(ids) < 2:
            continue

        duplicates += len(ids) - 1
        group_id = digest[:16]

        for file_id in ids:
            db.execute(
                """
                UPDATE files
                SET duplicate_group=?
                WHERE id=?
                """,
                (group_id, file_id),
            )

    db.commit()

    print("\nVERIFICATION SUMMARY")
    print("-" * 50)
    print("Verified:   ", verified)
    print("Missing:    ", missing)
    print("Changed:    ", changed)
    print("Duplicates: ", duplicates)

    event(
        db,
        "INFO",
        "VERIFY",
        json.dumps({
            "verified": verified,
            "missing": missing,
            "changed": changed,
            "duplicates": duplicates,
        }),
    )


# ============================================================
# DOWNLOAD PATHS
# ============================================================

def source_folder(row):
    return candidate_directory(
        row["source_type"] or "secondary"
    )


def unique_path(directory: Path, filename: str, url: str):
    directory.mkdir(parents=True, exist_ok=True)

    candidate = directory / safe_filename(filename)

    if not candidate.exists():
        return candidate

    suffix = hashlib.sha256(
        url.encode("utf-8")
    ).hexdigest()[:10]

    stem = candidate.stem
    ext = candidate.suffix

    return directory / f"{stem}_{suffix}{ext}"


def filename_from_headers(headers, url):
    disposition = headers.get("Content-Disposition")

    if disposition:
        message = Message()
        message["Content-Disposition"] = disposition

        filename = message.get_filename()

        if filename:
            return safe_filename(filename)

    return filename_from_url(url)


# ============================================================
# RESUMABLE DOWNLOAD
# ============================================================

def download_one(root: Path, db, row):
    url = row["url"]

    if row["manual_review"]:
        log("warning", f"Manual review required; skipped: {url}")
        return False

    if not row["download_enabled"]:
        log("info", f"Automatic download disabled: {url}")
        return False

    folder = root / source_folder(row)

    filename = row["filename"] or filename_from_url(url)

    destination = unique_path(
        folder,
        filename,
        url,
    )

    # If a record already exists for this URL and its file is present,
    # verify it instead of downloading another copy.

    existing = db.execute(
        """
        SELECT *
        FROM files
        WHERE url=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (url,),
    ).fetchone()

    if existing:
        existing_path = root / existing["path"]

        if existing_path.exists():
            try:
                current_hash = sha256_file(existing_path)

                if current_hash == existing["sha256"]:
                    log("info", f"Already verified: {existing['path']}")
                    return True

            except Exception:
                pass

    part = destination.with_name(destination.name + ".part")

    headers = {}

    offset = part.stat().st_size if part.exists() else 0

    if offset:
        headers["Range"] = f"bytes={offset}-"

    log("info", f"DOWNLOAD: {url}")

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                **headers,
            },
        )

        response = urllib.request.urlopen(
            request,
            timeout=DOWNLOAD_TIMEOUT,
        )

        status = response.getcode()

        # If the server ignores Range and returns a full response,
        # restart from zero instead of appending duplicate bytes.

        if offset and status != 206:
            response.close()
            offset = 0
            part.unlink(missing_ok=True)

            request = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT},
            )

            response = urllib.request.urlopen(
                request,
                timeout=DOWNLOAD_TIMEOUT,
            )

        headers_obj = response.headers

        filename = filename_from_headers(
            headers_obj,
            url,
        )

        if filename != destination.name:
            new_destination = unique_path(
                folder,
                filename,
                url,
            )

            destination = new_destination
            part = destination.with_name(
                destination.name + ".part"
            )

        content_length = headers_obj.get("Content-Length")

        expected_response_size = (
            int(content_length)
            if content_length and content_length.isdigit()
            else None
        )

        etag = headers_obj.get("ETag")
        last_modified = headers_obj.get("Last-Modified")

        mode = "ab" if offset and status == 206 else "wb"

        downloaded_this_session = 0

        with part.open(mode) as handle:

            while True:
                block = response.read(CHUNK_SIZE)

                if not block:
                    break

                handle.write(block)
                downloaded_this_session += len(block)

        response.close()

        actual_size = part.stat().st_size

        # Content-Length refers to the response body.
        # For a resumed 206 response, compare the newly received bytes.

        if (
            expected_response_size is not None
            and downloaded_this_session != expected_response_size
        ):
            raise IOError(
                "Downloaded response length mismatch: "
                f"expected {expected_response_size}, "
                f"received {downloaded_this_session}"
            )

        if actual_size <= 0:
            raise IOError("Downloaded file is empty")

        digest = sha256_file(part)

        destination.parent.mkdir(parents=True, exist_ok=True)
        part.replace(destination)

        relative = str(destination.relative_to(root))

        duplicate = db.execute(
            "SELECT path FROM files WHERE sha256=? LIMIT 1",
            (digest,),
        ).fetchone()

        duplicate_group = digest[:16] if duplicate else None

        db.execute(
            """
            INSERT INTO files
            (
                candidate_id,
                source_id,
                url,
                path,
                filename,
                size,
                sha256,
                etag,
                last_modified,
                downloaded_at,
                verification_status,
                duplicate_group
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                size=excluded.size,
                sha256=excluded.sha256,
                etag=excluded.etag,
                last_modified=excluded.last_modified,
                downloaded_at=excluded.downloaded_at,
                verification_status='VERIFIED',
                duplicate_group=excluded.duplicate_group
            """,
            (
                row["id"],
                row["source_id"],
                url,
                relative,
                destination.name,
                actual_size,
                digest,
                etag,
                last_modified,
                utc_now(),
                "VERIFIED",
                duplicate_group,
            ),
        )

        db.execute(
            """
            UPDATE candidates
            SET filename=?
            WHERE id=?
            """,
            (
                destination.name,
                row["id"],
            ),
        )

        db.commit()

        log(
            "info",
            f"COMPLETE: {relative} "
            f"({format_bytes(actual_size)}) "
            f"SHA256={digest}",
        )

        event(
            db,
            "INFO",
            "DOWNLOAD_COMPLETE",
            f"{relative}; size={actual_size}; sha256={digest}",
            url,
        )

        return True

    except urllib.error.HTTPError as exc:

        log(
            "error",
            f"HTTP ERROR {exc.code}: {url}",
        )

        db.execute(
            """
            UPDATE candidates
            SET status=?, error=?, last_checked=?
            WHERE id=?
            """,
            (
                exc.code,
                str(exc),
                utc_now(),
                row["id"],
            ),
        )

        db.commit()

        event(
            db,
            "ERROR",
            "DOWNLOAD_HTTP_ERROR",
            str(exc),
            url,
        )

        return False

    except Exception as exc:

        log(
            "error",
            f"DOWNLOAD FAILED: {url}: {exc}",
        )

        db.execute(
            """
            UPDATE candidates
            SET error=?, last_checked=?
            WHERE id=?
            """,
            (
                str(exc),
                utc_now(),
                row["id"],
            ),
        )

        db.commit()

        event(
            db,
            "ERROR",
            "DOWNLOAD_ERROR",
            str(exc),
            url,
        )

        return False


# ============================================================
# DOWNLOAD QUEUE
# ============================================================

def download_all(root: Path, db):
    rows = candidates_for_download(db)

    print("\nDOWNLOAD QUEUE")
    print("-" * 50)
    print("Items:", len(rows))

    known_size, unknown_count = estimate_download(db)

    usage = disk_status(root)

    if known_size > usage.free:
        print("\nWARNING: Known download size exceeds free space.")
        print("The archive may not fit on this filesystem.")

        if not ask_yes_no("Continue anyway?", False):
            return

    elif known_size > usage.free * 0.9:
        print("\nWARNING: Download will consume most free space.")

        if not ask_yes_no("Continue anyway?", False):
            return

    if unknown_count:
        print(
            "\nSome resources have unknown sizes. "
            "The final download size may be larger."
        )

    if not ask_yes_no(
        "Start downloading the available archive?",
        False,
    ):
        print("\nDownload cancelled. Existing archive will still be verified.")
        inventory(root, db)
        verify_inventory(root, db)
        return

    completed = 0
    failed = 0

    for index, row in enumerate(rows, 1):

        print(
            f"\n[{index}/{len(rows)}] "
            f"{row['source_name'] or 'Unknown source'}"
        )

        success = False

        for attempt in range(1, RETRY_ATTEMPTS + 1):

            success = download_one(root, db, row)

            if success:
                break

            if attempt < RETRY_ATTEMPTS:
                log(
                    "warning",
                    f"Retry {attempt}/{RETRY_ATTEMPTS}: {row['url']}",
                )

                time.sleep(RETRY_DELAY * attempt)

        if success:
            completed += 1
        else:
            failed += 1

        time.sleep(DOWNLOAD_DELAY)

    print("\nDOWNLOAD SUMMARY")
    print("-" * 50)
    print("Completed:", completed)
    print("Failed:   ", failed)

    inventory(root, db)
    verify_inventory(root, db)


# ============================================================
# RETRY FAILED URLS
# ============================================================

def retry_failed_urls(root: Path, db):
    rows = db.execute(
        """
        SELECT c.*, s.name AS source_name,
               s.source_type AS source_type,
               s.trust_level AS trust_level
        FROM candidates c
        LEFT JOIN sources s ON s.id=c.source_id
        WHERE
            c.status IS NULL
            OR c.status < 200
            OR c.status >= 400
            OR c.error IS NOT NULL
        ORDER BY c.id
        """
    ).fetchall()

    print("\nFAILED URLS:", len(rows))

    if not rows:
        print("No failed URLs.")
        return

    for row in rows:
        print(
            f"[{row['status']}] {row['url']} "
            f":: {row['error'] or ''}"
        )

    if not ask_yes_no("Retry these URLs?", False):
        return

    for index, row in enumerate(rows, 1):

        print(f"\n[{index}/{len(rows)}] {row['url']}")

        success = False

        for attempt in range(1, RETRY_ATTEMPTS + 1):

            status, ctype, size, final_url, error = probe_url(
                row["url"]
            )

            db.execute(
                """
                UPDATE candidates
                SET status=?,
                    content_type=?,
                    expected_size=?,
                    last_checked=?,
                    error=?
                WHERE id=?
                """,
                (
                    status,
                    ctype,
                    size,
                    utc_now(),
                    error,
                    row["id"],
                ),
            )

            db.commit()

            if is_success(status):
                success = True
                break

            time.sleep(RETRY_DELAY * attempt)

        if success and row["download_enabled"] and not row["manual_review"]:
            refreshed = db.execute(
                """
                SELECT c.*, s.name AS source_name,
                       s.source_type AS source_type,
                       s.trust_level AS trust_level
                FROM candidates c
                LEFT JOIN sources s ON s.id=c.source_id
                WHERE c.id=?
                """,
                (row["id"],),
            ).fetchone()

            download_one(root, db, refreshed)

    inventory(root, db)
    verify_inventory(root, db)


# ============================================================
# STATUS
# ============================================================

def show_status(root: Path, db):
    print("\nARCHIVE STATUS")
    print("=" * 60)

    source_count = db.execute(
        "SELECT COUNT(*) FROM sources"
    ).fetchone()[0]

    available_sources = db.execute(
        """
        SELECT COUNT(*) FROM sources
        WHERE status >= 200 AND status < 400
        """
    ).fetchone()[0]

    candidate_count = db.execute(
        "SELECT COUNT(*) FROM candidates"
    ).fetchone()[0]

    available_candidates = db.execute(
        """
        SELECT COUNT(*) FROM candidates
        WHERE status >= 200 AND status < 400
        """
    ).fetchone()[0]

    failed_candidates = db.execute(
        """
        SELECT COUNT(*) FROM candidates
        WHERE status IS NULL
           OR status < 200
           OR status >= 400
        """
    ).fetchone()[0]

    manual_count = db.execute(
        """
        SELECT COUNT(*) FROM candidates
        WHERE manual_review=1
        """
    ).fetchone()[0]

    file_count = db.execute(
        "SELECT COUNT(*) FROM files"
    ).fetchone()[0]

    total_size = db.execute(
        "SELECT SUM(size) FROM files"
    ).fetchone()[0] or 0

    print("Sources:             ", source_count)
    print("Available sources:   ", available_sources)
    print("Discovered URLs:     ", candidate_count)
    print("Available URLs:      ", available_candidates)
    print("Failed URLs:         ", failed_candidates)
    print("Manual review URLs:  ", manual_count)
    print("Local files:         ", file_count)
    print("Local file size:     ", format_bytes(total_size))

    disk_status(root)


# ============================================================
# MANIFEST EXPORT
# ============================================================

def export_manifests(root: Path, db):
    manifest_dir = root / "07_MANIFESTS"
    manifest_dir.mkdir(parents=True, exist_ok=True)

    candidates = db.execute(
        """
        SELECT c.*, s.name AS source_name,
               s.source_type, s.trust_level
        FROM candidates c
        LEFT JOIN sources s ON s.id=c.source_id
        ORDER BY c.id
        """
    ).fetchall()

    with (manifest_dir / "master_manifest.jsonl").open(
        "w",
        encoding="utf-8",
    ) as handle:

        for row in candidates:
            handle.write(
                json.dumps(
                    dict(row),
                    ensure_ascii=False,
                ) + "\n"
            )

    files = db.execute(
        "SELECT * FROM files ORDER BY path"
    ).fetchall()

    with (manifest_dir / "local_files.jsonl").open(
        "w",
        encoding="utf-8",
    ) as handle:

        for row in files:
            handle.write(
                json.dumps(
                    dict(row),
                    ensure_ascii=False,
                ) + "\n"
            )

    sources = db.execute(
        "SELECT * FROM sources ORDER BY id"
    ).fetchall()

    with (manifest_dir / "sources.json").open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            [dict(row) for row in sources],
            handle,
            ensure_ascii=False,
            indent=2,
        )

    failed = db.execute(
        """
        SELECT url, status, error, last_checked
        FROM candidates
        WHERE status IS NULL
           OR status < 200
           OR status >= 400
        """
    ).fetchall()

    with (manifest_dir / "failed_urls.json").open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            [dict(row) for row in failed],
            handle,
            ensure_ascii=False,
            indent=2,
        )

    duplicates = db.execute(
        """
        SELECT duplicate_group, COUNT(*) AS count,
               GROUP_CONCAT(path, ' | ') AS paths
        FROM files
        WHERE duplicate_group IS NOT NULL
        GROUP BY duplicate_group
        """
    ).fetchall()

    with (manifest_dir / "duplicates.json").open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            [dict(row) for row in duplicates],
            handle,
            ensure_ascii=False,
            indent=2,
        )

    print("Manifests exported to:", manifest_dir)


# ============================================================
# DISCOVERY WORKFLOW
# ============================================================

def run_discovery(root: Path, db):
    register_sources(db)

    disk_status(root)

    print("\n[PHASE 1] SOURCE CHECK")
    probe_sources(db)

    print("\n[PHASE 2] DISCOVERY")
    discover_all(db)

    print("\n[PHASE 3] CANDIDATE PREFLIGHT")
    probe_candidates(db)

    print("\n[PHASE 4] SIZE ESTIMATION")
    estimate_download(db)

    show_status(root, db)

    if ask_yes_no(
        "\nProceed to download?",
        False,
    ):
        download_all(root, db)

    else:
        print("\nDownload skipped.")
        print("Existing archive will be inventoried and verified.")

        inventory(root, db)
        verify_inventory(root, db)

    export_manifests(root, db)


# ============================================================
# MONITORING
# ============================================================

def monitor_mode(root: Path, db):
    print("\nMONITORING MODE")
    print("Interval:", MONITOR_INTERVAL_HOURS, "hours")
    print("Press CTRL+C to stop.")

    while True:
        try:
            print("\n" + "=" * 60)
            print("MONITOR CYCLE:", utc_now())
            print("=" * 60)

            register_sources(db)
            probe_sources(db)
            discover_all(db)
            probe_candidates(db)

            inventory(root, db)
            verify_inventory(root, db)

            export_manifests(root, db)

            log(
                "info",
                "Monitoring cycle completed.",
            )

            time.sleep(
                MONITOR_INTERVAL_HOURS * 3600
            )

        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
            break

        except Exception as exc:
            log(
                "error",
                f"Monitoring cycle failed: {exc}",
            )

            time.sleep(60)


# ============================================================
# INITIALIZATION
# ============================================================

def first_run_check(root: Path, db):
    print("\nINITIAL ARCHIVE CHECK")
    print("-" * 50)

    file_count = sum(
        1 for path in root.rglob("*")
        if path.is_file()
        and path.name != DATABASE_NAME
        and not path.name.endswith(".part")
    )

    print("Existing files:", file_count)

    if file_count == 0:
        print("Archive appears empty.")
        inventory(root, db)
        return

    print("Existing archive detected.")
    print("Only the selected archive directory will be scanned.")

    if ask_yes_no(
        "Inventory and verify existing files now?",
        True,
    ):
        inventory(root, db)
        verify_inventory(root, db)


# ============================================================
# MAIN
# ============================================================

def main():
    banner()

    root = choose_root()

    initialize_layout(root)
    setup_logging(root)

    log("info", f"Archive root: {root}")

    db = connect_db(root)

    try:
        register_sources(db)

        first_run_check(root, db)

        while True:
            menu()

            choice = input("Select operation: ").strip()

            if choice == "1":
                run_discovery(root, db)

            elif choice == "2":
                inventory(root, db)
                verify_inventory(root, db)
                export_manifests(root, db)

            elif choice == "3":
                show_status(root, db)

            elif choice == "4":
                retry_failed_urls(root, db)

            elif choice == "5":
                monitor_mode(root, db)

            elif choice == "6":
                disk_status(root)
                check_smart()

            elif choice == "7":
                export_manifests(root, db)

            elif choice == "0":
                print("\nExiting.")
                break

            else:
                print("Unknown command.")

    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    finally:
        db.commit()
        db.close()

        print("\nArchive session closed.")


if __name__ == "__main__":
    main()

# modules/database.py

import sqlite3
from datetime import datetime
import json
from typing import Optional, List, Dict, Any, Tuple

DB_FILE = "attack_surface.db"


def initialize_database() -> None:
    """Veritabanı tablosunu oluştur."""
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            score INTEGER NOT NULL,
            rating TEXT NOT NULL,
            findings TEXT,
            report_json TEXT,
            scan_date TEXT NOT NULL
        )
    """)

    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN findings TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN report_json TEXT")
    except sqlite3.OperationalError:
        pass

    connection.commit()
    connection.close()


def save_scan_result(
    domain: str,
    score: int,
    rating: str,
    findings: List[Dict[str, Any]],
    report_data: Dict[str, Any]
) -> None:
    """Tarama sonucunu veritabanına kaydet."""
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans (
            domain,
            score,
            rating,
            findings,
            report_json,
            scan_date
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        domain,
        score,
        rating,
        json.dumps(findings, ensure_ascii=False),
        json.dumps(report_data, ensure_ascii=False),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_scan_history(domain: str) -> List[Tuple[str, int, str]]:
    """Domain geçmişini getir."""
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT scan_date, score, rating
        FROM scans
        WHERE domain = ?
        ORDER BY scan_date DESC
    """, (domain,))

    results = cursor.fetchall()

    connection.close()

    return results


def get_previous_scan(
    domain: str
) -> Optional[Tuple]:
    """Bir önceki taramayı getir."""
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            scan_date,
            score,
            rating,
            findings,
            report_json
        FROM scans
        WHERE domain = ?
        ORDER BY scan_date DESC
        LIMIT 1 OFFSET 1
    """, (domain,))

    result = cursor.fetchone()

    connection.close()

    if not result:
        return None

    try:
        findings = json.loads(result[3]) if result[3] else []
    except Exception:
        findings = []

    try:
        report_json = json.loads(result[4]) if result[4] else {}
    except Exception:
        report_json = {}

    return (
        result[0],  # scan_date
        result[1],  # score
        result[2],  # rating
        findings,
        report_json
    )

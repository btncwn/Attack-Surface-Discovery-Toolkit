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
            findings TEXT,  -- JSON olarak findings
            scan_date TEXT NOT NULL
        )
    """)

    # Eski tabloyu güncelle (eğer findings sütunu yoksa)
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN findings TEXT")
    except sqlite3.OperationalError:
        pass  # Sütun zaten var

    connection.commit()
    connection.close()


def save_scan_result(
    domain: str,
    score: int,
    rating: str,
    findings: List[Dict[str, Any]]
) -> None:
    """Tarama sonucunu veritabanına kaydet."""
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans (domain, score, rating, findings, scan_date)
        VALUES (?, ?, ?, ?, ?)
    """, (
        domain,
        score,
        rating,
        # findings'i JSON string olarak kaydet
        json.dumps(findings, ensure_ascii=False),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_scan_history(domain: str) -> List[Tuple[str, int, str]]:
    """Domain'in tüm tarama geçmişini getir."""
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
) -> Optional[Tuple[str, int, str, List[Dict[str, Any]]]]:
    """Domain'in bir önceki tarama sonucunu getir."""
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT scan_date, score, rating, findings
        FROM scans
        WHERE domain = ?
        ORDER BY scan_date DESC
        LIMIT 1 OFFSET 1
    """, (domain,))

    result = cursor.fetchone()
    connection.close()

    if result:
        # findings JSON string'ini parse et
        try:
            findings = json.loads(result[3]) if result[3] else []
        except json.JSONDecodeError:
            findings = []
        return (result[0], result[1], result[2], findings)

    return None

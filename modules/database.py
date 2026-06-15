import sqlite3
from datetime import datetime


DB_FILE = "attack_surface.db"


def initialize_database():
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            score INTEGER NOT NULL,
            rating TEXT NOT NULL,
            scan_date TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan_result(domain: str, score: int, rating: str):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans (domain, score, rating, scan_date)
        VALUES (?, ?, ?, ?)
    """, (
        domain,
        score,
        rating,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_scan_history(domain: str):
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


def get_previous_scan(domain: str):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT scan_date, score, rating
        FROM scans
        WHERE domain = ?
        ORDER BY scan_date DESC
        LIMIT 1 OFFSET 1
    """, (domain,))

    result = cursor.fetchone()

    connection.close()

    return result

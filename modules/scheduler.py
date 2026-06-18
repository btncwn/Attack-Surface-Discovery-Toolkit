# modules/scheduler.py
import sqlite3
import schedule
import time
import threading
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json

from modules.database import get_scan_history
from modules.change_detection import compare_findings


# ============================================================
# DOMAIN VALIDATION
# ============================================================

def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name format.
    Supports: example.com, sub.example.co.uk
    """
    if not domain or len(domain) > 253:
        return False

    # Basic domain regex
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))


# ============================================================
# SCHEDULER (Singleton)
# ============================================================

class ScanScheduler:
    """Automated scan scheduler with dashboard support (Singleton)."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance

    def __init__(self, db_path: str = "attack_surface.db"):
        if hasattr(self, '_initialized') and self._initialized:
            return

        self.db_path = db_path
        self.running = False
        self.thread = None
        self._job_registry = {}  # domain -> job
        self._initialized = True
        self._init_db()

    def _init_db(self):
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scheduled_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    frequency TEXT NOT NULL,
                    time TEXT NOT NULL,
                    recipient_email TEXT,
                    last_run TEXT,
                    next_run TEXT,
                    active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    score INTEGER,
                    rating TEXT,
                    findings_json TEXT,
                    status TEXT DEFAULT 'completed',
                    error TEXT
                )
            """)

            conn.commit()

    def add_schedule(self, domain: str, frequency: str = "weekly",
                     time: str = "09:00", recipient: str = None) -> bool:
        """Add or update a scheduled scan with validation."""

        # 🆕 Domain validation
        if not is_valid_domain(domain):
            print(f"[ERROR] Invalid domain: {domain}")
            return False

        if frequency not in ["daily", "weekly", "monthly"]:
            print(f"[ERROR] Invalid frequency: {frequency}")
            return False

        try:
            hour, minute = map(int, time.split(':'))
            if not (0 <= hour < 24 and 0 <= minute < 60):
                raise ValueError("Invalid time format")
        except:
            print(f"[ERROR] Invalid time format: {time}")
            return False

        try:
            next_run = self._calculate_next_run(frequency, time)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO scheduled_scans 
                    (domain, frequency, time, recipient_email, next_run, active)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (domain, frequency, time, recipient, next_run))
                conn.commit()

            # 🆕 Reschedule if running
            if self.running:
                self._schedule_job(domain)

            return True
        except Exception as e:
            print(f"[ERROR] Failed to add schedule for {domain}: {e}")
            return False

    def _calculate_next_run(self, frequency: str, time: str) -> str:
        """Calculate next run time based on frequency."""
        today = datetime.now()
        hour, minute = map(int, time.split(':'))

        if frequency == "daily":
            next_date = today.replace(
                hour=hour, minute=minute, second=0, microsecond=0)
            if next_date <= today:
                next_date += timedelta(days=1)
        elif frequency == "weekly":
            days_until_monday = (0 - today.weekday()) % 7
            next_date = (today + timedelta(days=days_until_monday)).replace(
                hour=hour, minute=minute, second=0, microsecond=0
            )
            if next_date <= today:
                next_date += timedelta(days=7)
        elif frequency == "monthly":
            next_date = today.replace(
                day=1, hour=hour, minute=minute, second=0, microsecond=0)
            if next_date <= today:
                next_date = (next_date + timedelta(days=32)).replace(day=1)
        else:
            return ""

        return next_date.isoformat()

    def _schedule_job(self, domain: str):
        """Schedule a job for a domain."""
        schedule_data = self.get_schedule(domain)
        if not schedule_data or not schedule_data.get('active', 1):
            return

        frequency = schedule_data.get('frequency', 'weekly')
        scan_time = schedule_data.get('time', '09:00')

        # 🆕 Clear existing job
        if domain in self._job_registry:
            schedule.cancel_job(self._job_registry[domain])
            del self._job_registry[domain]

        if frequency == "daily":
            job = schedule.every().day.at(scan_time).do(self._run_scan_and_log, domain)
        elif frequency == "weekly":
            job = schedule.every().monday.at(scan_time).do(self._run_scan_and_log, domain)
        elif frequency == "monthly":
            job = schedule.every().day.at(scan_time).do(self._check_monthly_run, domain)
        else:
            return

        self._job_registry[domain] = job

    def _check_monthly_run(self, domain: str):
        """Check if today is the 1st of the month for monthly scans."""
        if datetime.now().day == 1:
            self._run_scan_and_log(domain)

    def _run_scan_and_log(self, domain: str):
        """Run scan and log results."""
        try:
            print(f"[{datetime.now()}] Running scheduled scan for {domain}")

            # Import scan functions (lazy import to avoid circular)
            from modules.dns_lookup import get_dns_records
            from modules.whois_lookup import get_whois_info
            from modules.ssl_checker import get_ssl_certificate
            from modules.port_scanner import scan_ports
            from modules.subdomain_enum import enumerate_subdomains
            from modules.tech_fingerprint import fingerprint_technology
            from modules.risk_engine import generate_findings, calculate_attack_surface_score
            from modules.security_headers import check_security_headers
            from modules.ct_discovery import get_ct_subdomains
            from modules.asset_discovery import compare_discovered_assets
            from modules.cve_lookup import correlate_cves
            from modules.database import save_scan_result

            # Run scan
            dns_records = get_dns_records(domain)
            whois_info = get_whois_info(domain)
            ssl_info = get_ssl_certificate(domain)
            open_ports = scan_ports(domain)
            subdomains = enumerate_subdomains(domain)

            ct_results = get_ct_subdomains(domain)
            ct_subdomains = ct_results.get("subdomains", [])
            asset_analysis = compare_discovered_assets(
                subdomains, ct_subdomains)

            tech_info = fingerprint_technology(domain)
            security_headers = check_security_headers(domain)
            cve_results = correlate_cves(tech_info, dns_records)

            report_data = {
                "domain": domain,
                "dns_records": dns_records,
                "whois_information": whois_info,
                "ssl_information": ssl_info,
                "open_ports": open_ports,
                "subdomains": subdomains,
                "asset_analysis": asset_analysis,
                "technology_fingerprint": tech_info,
                "security_headers": security_headers,
                "cve_correlation": cve_results,
            }

            findings = generate_findings(report_data)
            report_data["findings"] = findings

            score = calculate_attack_surface_score(findings)
            report_data["attack_surface_score"] = score

            # Save to database
            save_scan_result(domain, score["score"], score["rating"], findings)

            # Update scheduled scan
            self._update_schedule(domain, report_data)

            # Log scan
            self._log_scan(domain, score["score"], score["rating"], findings)

            print(f"[{datetime.now()}] Scheduled scan completed for {domain}")

        except Exception as e:
            print(f"[ERROR] Scheduled scan for {domain} failed: {e}")
            self._log_scan(domain, 0, "Failed", [],
                           status="failed", error=str(e))

    def _update_schedule(self, domain: str, report_data: dict):
        """Update schedule after scan."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT frequency, time FROM scheduled_scans WHERE domain=?", (domain,))
            row = cursor.fetchone()

            if row:
                frequency, time = row
                next_run = self._calculate_next_run(frequency, time)

                cursor.execute("""
                    UPDATE scheduled_scans 
                    SET last_run = ?, next_run = ?
                    WHERE domain = ?
                """, (datetime.now().isoformat(), next_run, domain))
                conn.commit()

    def _log_scan(self, domain: str, score: int, rating: str, findings: list,
                  status: str = "completed", error: str = None):
        """Log a scan result."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs (domain, scan_date, score, rating, findings_json, status, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                domain,
                datetime.now().isoformat(),
                score,
                rating,
                json.dumps(findings),
                status,
                error
            ))
            conn.commit()

    def get_schedule(self, domain: str) -> Optional[Dict]:
        """Get schedule for a domain."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain, frequency, time, recipient_email, last_run, next_run, active
                FROM scheduled_scans WHERE domain=?
            """, (domain,))
            row = cursor.fetchone()
            if row:
                return {
                    "domain": row[0],
                    "frequency": row[1],
                    "time": row[2],
                    "recipient": row[3],
                    "last_run": row[4],
                    "next_run": row[5],
                    "active": row[6]
                }
            return None

    def get_all_schedules(self) -> List[Dict]:
        """Get all schedules."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain, frequency, time, recipient_email, last_run, next_run, active
                FROM scheduled_scans
                ORDER BY domain
            """)
            rows = cursor.fetchall()
            return [
                {
                    "domain": row[0],
                    "frequency": row[1],
                    "time": row[2],
                    "recipient": row[3],
                    "last_run": row[4],
                    "next_run": row[5],
                    "active": row[6]
                }
                for row in rows
            ]

    def get_scan_logs(self, domain: str = None, limit: int = 50) -> List[Dict]:
        """Get scan logs."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            if domain:
                cursor.execute("""
                    SELECT domain, scan_date, score, rating, status, error
                    FROM scan_logs
                    WHERE domain = ?
                    ORDER BY scan_date DESC
                    LIMIT ?
                """, (domain, limit))
            else:
                cursor.execute("""
                    SELECT domain, scan_date, score, rating, status, error
                    FROM scan_logs
                    ORDER BY scan_date DESC
                    LIMIT ?
                """, (limit,))

            rows = cursor.fetchall()
            return [
                {
                    "domain": row[0],
                    "scan_date": row[1],
                    "score": row[2],
                    "rating": row[3],
                    "status": row[4],
                    "error": row[5]
                }
                for row in rows
            ]

    def remove_schedule(self, domain: str) -> bool:
        """Remove a scheduled scan and clean up memory."""
        try:
            # 🆕 Cancel job in memory
            if domain in self._job_registry:
                schedule.cancel_job(self._job_registry[domain])
                del self._job_registry[domain]

            # Deactivate in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE scheduled_scans SET active=0 WHERE domain=?", (domain,))
                conn.commit()

            print(f"[{datetime.now()}] Removed schedule for {domain}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to remove schedule for {domain}: {e}")
            return False

    def start(self):
        """Start scheduler in background thread."""
        if self.running:
            return

        self.running = True

        # Schedule all active jobs
        schedules = self.get_all_schedules()
        for schedule_data in schedules:
            if schedule_data.get('active', 1):
                self._schedule_job(schedule_data['domain'])

        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        print(f"[{datetime.now()}] Scan scheduler started with {len(schedules)} jobs")

    def _run_loop(self):
        while self.running:
            schedule.run_pending()
            time.sleep(60)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print(f"[{datetime.now()}] Scan scheduler stopped")

    def get_status(self) -> Dict:
        """Get scheduler status."""
        return {
            "running": self.running,
            "jobs": len(self._job_registry),
            "schedules": len(self.get_all_schedules())
        }

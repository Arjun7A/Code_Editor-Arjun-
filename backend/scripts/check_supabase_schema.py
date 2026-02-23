"""
Validate Security Gate core tables on Supabase/Postgres.

What it checks:
1. DATABASE_URL points to a Postgres database.
2. Required tables/columns exist.
3. The current DB user can insert into the 3 core tables.

Usage:
  python scripts/check_supabase_schema.py
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Set

import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parents[1] / ".env")


EXPECTED_COLUMNS: Dict[str, Set[str]] = {
    "pull_requests": {
        "id",
        "repo_name",
        "pr_number",
        "pr_url",
        "status",
        "risk_score",
        "verdict",
        "files_changed",
        "lines_added",
        "lines_deleted",
        "author_name",
        "feature_importance",
        "created_at",
        "updated_at",
    },
    "scan_results": {
        "id",
        "pr_id",
        "tool",
        "findings",
        "severity",
        "summary",
        "execution_time",
        "severity_counts",
        "created_at",
    },
    "audit_logs": {
        "id",
        "pr_id",
        "blockchain_hash",
        "blockchain_tx",
        "decision",
        "risk_data",
        "timestamp",
    },
}


def _get_db_url() -> str:
    db_url = os.getenv("DATABASE_URL", "").strip()
    if not db_url:
        print("ERROR: DATABASE_URL is empty.")
        sys.exit(1)
    if not db_url.startswith("postgresql"):
        print(f"ERROR: DATABASE_URL must be Postgres for Supabase. Current: {db_url}")
        sys.exit(1)
    return db_url


def _fetch_columns(cur, table: str) -> Set[str]:
    cur.execute(
        """
        select column_name
        from information_schema.columns
        where table_schema = 'public' and table_name = %s
        """,
        (table,),
    )
    return {row[0] for row in cur.fetchall()}


def _verify_schema(cur) -> bool:
    ok = True
    for table, expected in EXPECTED_COLUMNS.items():
        got = _fetch_columns(cur, table)
        missing = sorted(expected - got)
        if missing:
            ok = False
            print(f"ERROR: table '{table}' is missing columns: {missing}")
        else:
            print(f"OK: table '{table}' columns look correct ({len(got)} columns present)")
    return ok


def _write_smoke_test(cur) -> None:
    stamp = int(time.time())
    repo_name = f"smoke/repo-{uuid.uuid4().hex[:8]}"
    pr_number = stamp % 1000000

    cur.execute(
        """
        insert into public.pull_requests
            (repo_name, pr_number, pr_url, status, risk_score, verdict, files_changed, lines_added, lines_deleted, author_name, feature_importance)
        values
            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        returning id
        """,
        (
            repo_name,
            pr_number,
            f"https://github.com/{repo_name}/pull/{pr_number}",
            "completed",
            42.0,
            "MANUAL_REVIEW",
            3,
            30,
            10,
            "schema-checker",
            Json({"files_changed": 0.25}),
        ),
    )
    pr_id = cur.fetchone()[0]

    cur.execute(
        """
        insert into public.scan_results
            (pr_id, tool, findings, severity, summary, execution_time, severity_counts)
        values
            (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            pr_id,
            "semgrep",
            Json([{"id": "smoke-1", "severity": "high"}]),
            "high",
            "smoke semgrep row",
            1.23,
            Json({"critical": 0, "high": 1, "medium": 0, "low": 0}),
        ),
    )

    cur.execute(
        """
        insert into public.audit_logs
            (pr_id, blockchain_hash, blockchain_tx, decision, risk_data)
        values
            (%s, %s, %s, %s, %s)
        """,
        (
            pr_id,
            "0xsmokehash",
            "0xsmoketx",
            "MANUAL_REVIEW",
            Json({"risk_score": 42.0}),
        ),
    )

    print("OK: transactional insert into pull_requests/scan_results/audit_logs succeeded")


def main() -> int:
    db_url = _get_db_url()
    try:
        conn = psycopg2.connect(db_url)
    except Exception as exc:
        print(f"ERROR: failed to connect to database: {exc}")
        return 1

    try:
        with conn:
            with conn.cursor() as cur:
                schema_ok = _verify_schema(cur)
                if not schema_ok:
                    return 1

                # Run write check inside transaction and roll back explicitly.
                conn.rollback()
                conn.autocommit = False
                with conn.cursor() as smoke_cur:
                    _write_smoke_test(smoke_cur)
                    conn.rollback()
        print("SUCCESS: Supabase schema + write access checks passed")
        return 0
    except Exception as exc:
        print(f"ERROR: schema/write verification failed: {exc}")
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())

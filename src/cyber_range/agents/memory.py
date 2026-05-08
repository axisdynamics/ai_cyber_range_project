"""
cyber_range.agents.memory
==========================
SQLite-backed persistent memory for the Hermes multi-agent system.

The memory persists across runs and enables:
  - Gap accumulation: técnicas que persisten sin cobertura entre runs
  - Learning: qué escenarios produjeron findings de alta calidad antes
  - Run history: timeline completo de ejecuciones
  - Prioritization: técnicas más críticas basadas en historial

Schema:
    runs        — resumen de cada ejecución
    findings    — todos los findings acumulados
    gaps        — gaps de detección persistentes (presentes en N+ runs)
    learning    — por técnica: confidence, typical_score, reproducible_rate
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


DB_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT,
    findings_count INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    coverage_pct    REAL DEFAULT 0,
    gap_pct         REAL DEFAULT 0,
    profile         TEXT,
    raw_json        TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    asset           TEXT,
    technique_id    TEXT,
    severity        TEXT,
    detection_status TEXT,
    score           REAL,
    reproducible    INTEGER DEFAULT 0,
    recorded_at     TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS gaps (
    technique_id    TEXT NOT NULL,
    asset           TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    occurrence_count INTEGER DEFAULT 1,
    max_score       REAL DEFAULT 0,
    PRIMARY KEY (technique_id, asset)
);

CREATE TABLE IF NOT EXISTS learning (
    technique_id        TEXT PRIMARY KEY,
    total_runs          INTEGER DEFAULT 0,
    reproducible_runs   INTEGER DEFAULT 0,
    avg_score           REAL DEFAULT 0,
    gap_runs            INTEGER DEFAULT 0,
    last_seen           TEXT,
    notes               TEXT
);
"""


@dataclass
class PersistentGap:
    technique_id:    str
    asset:           str
    occurrence_count: int
    max_score:       float
    first_seen:      str
    last_seen:       str


@dataclass
class TechniqueLearning:
    technique_id:      str
    total_runs:        int
    reproducible_rate: float  # 0-1
    avg_score:         float
    gap_rate:          float  # fraction of runs where detection_status == gap
    last_seen:         Optional[str]


class AgentMemory:
    """
    Persistent cross-run memory for Hermes agents.

    Usage:
        mem = AgentMemory(Path("artifacts/agent_memory.db"))
        mem.remember_run(summary_dict)
        gaps = mem.get_persistent_gaps(min_occurrences=2)
        priority = mem.get_priority_techniques(scope=["T1078","T1059"])
    """

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as c:
            c.executescript(SCHEMA)
            version = c.execute("SELECT version FROM schema_version").fetchone()
            if not version:
                c.execute("INSERT INTO schema_version VALUES (?)", (DB_VERSION,))

    # ── Run memory ────────────────────────────────────────────────────────────

    def remember_run(self, summary: Dict[str, Any]) -> None:
        """Persist a run summary and update all derived tables."""
        run_id = summary.get("run_id", "")
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as c:
            c.execute("""
                INSERT OR REPLACE INTO runs
                    (run_id, started_at, finished_at, status,
                     findings_count, critical_count, coverage_pct, gap_pct, profile, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                run_id,
                summary.get("started_at", now),
                summary.get("finished_at", now),
                summary.get("status", "unknown"),
                summary.get("findings_count", 0),
                summary.get("critical_count", 0),
                min(float(summary.get("coverage_pct", 0)), 100.0),
                min(float(summary.get("detection_gap_pct", 0)), 100.0),
                summary.get("profile", ""),
                json.dumps(summary),
            ))

    def remember_findings(self, run_id: str, findings: List[Dict]) -> None:
        """Persist findings and update gaps + learning tables."""
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as c:
            for f in findings:
                fid  = f.get("id", "")
                tech = f.get("technique_id", "")
                asset = f.get("asset", "")
                det  = f.get("detection_status", "")
                score = float(f.get("score", 0))
                repro = 1 if f.get("reproducible") else 0

                if not fid or not tech:
                    continue

                # Insert finding
                c.execute("""
                    INSERT OR IGNORE INTO findings
                        (id, run_id, asset, technique_id, severity,
                         detection_status, score, reproducible, recorded_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (fid, run_id, asset, tech,
                      f.get("severity", ""), det, score, repro, now))

                # Update gaps table
                if det == "gap" and tech and asset:
                    existing = c.execute(
                        "SELECT occurrence_count, max_score FROM gaps WHERE technique_id=? AND asset=?",
                        (tech, asset)
                    ).fetchone()
                    if existing:
                        c.execute("""
                            UPDATE gaps
                            SET last_seen=?, occurrence_count=occurrence_count+1,
                                max_score=MAX(max_score, ?)
                            WHERE technique_id=? AND asset=?
                        """, (now, score, tech, asset))
                    else:
                        c.execute("""
                            INSERT INTO gaps (technique_id, asset, first_seen, last_seen,
                                              occurrence_count, max_score)
                            VALUES (?,?,?,?,1,?)
                        """, (tech, asset, now, now, score))

                # Update learning table
                existing_l = c.execute(
                    "SELECT * FROM learning WHERE technique_id=?", (tech,)
                ).fetchone()
                if existing_l:
                    old_avg = existing_l["avg_score"]
                    old_n   = existing_l["total_runs"]
                    new_avg = (old_avg * old_n + score) / (old_n + 1)
                    c.execute("""
                        UPDATE learning
                        SET total_runs=total_runs+1,
                            reproducible_runs=reproducible_runs+?,
                            avg_score=?,
                            gap_runs=gap_runs+?,
                            last_seen=?
                        WHERE technique_id=?
                    """, (repro, round(new_avg, 2),
                          1 if det == "gap" else 0,
                          now, tech))
                else:
                    c.execute("""
                        INSERT INTO learning
                            (technique_id, total_runs, reproducible_runs,
                             avg_score, gap_runs, last_seen)
                        VALUES (?,1,?,?,?,?)
                    """, (tech, repro, score, 1 if det == "gap" else 0, now))

    # ── Gap intelligence ──────────────────────────────────────────────────────

    def get_persistent_gaps(self, min_occurrences: int = 2) -> List[PersistentGap]:
        """Return gaps seen in multiple runs — the hardest problems."""
        with self._conn() as c:
            rows = c.execute("""
                SELECT technique_id, asset, occurrence_count, max_score, first_seen, last_seen
                FROM gaps
                WHERE occurrence_count >= ?
                ORDER BY max_score DESC, occurrence_count DESC
            """, (min_occurrences,)).fetchall()
        return [PersistentGap(**dict(r)) for r in rows]

    def get_all_gaps(self) -> List[PersistentGap]:
        """All known gaps (even first-time)."""
        with self._conn() as c:
            rows = c.execute("""
                SELECT technique_id, asset, occurrence_count, max_score, first_seen, last_seen
                FROM gaps ORDER BY max_score DESC
            """).fetchall()
        return [PersistentGap(**dict(r)) for r in rows]

    # ── Learning ──────────────────────────────────────────────────────────────

    def get_technique_learning(self, technique_id: str) -> Optional[TechniqueLearning]:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM learning WHERE technique_id=?", (technique_id,)
            ).fetchone()
        if not row:
            return None
        n = row["total_runs"]
        return TechniqueLearning(
            technique_id=row["technique_id"],
            total_runs=n,
            reproducible_rate=round(row["reproducible_runs"] / n, 2) if n else 0.0,
            avg_score=row["avg_score"],
            gap_rate=round(row["gap_runs"] / n, 2) if n else 0.0,
            last_seen=row["last_seen"],
        )

    def get_priority_techniques(
        self,
        scope: List[str],
        top_n: int = 8,
    ) -> List[str]:
        """
        Return up to top_n techniques from scope, ordered by priority.

        Priority: techniques with high gap_rate AND high avg_score come first.
        New techniques (never seen) come last — let memory drive focus.
        """
        if not scope:
            return []

        with self._conn() as c:
            placeholders = ",".join("?" * len(scope))
            rows = c.execute(f"""
                SELECT technique_id,
                       gap_runs * 1.0 / total_runs AS gap_rate,
                       avg_score
                FROM learning
                WHERE technique_id IN ({placeholders})
                ORDER BY gap_rate DESC, avg_score DESC
                LIMIT ?
            """, (*scope, top_n)).fetchall()

        known = [r["technique_id"] for r in rows]
        # Add unknown techniques (no history yet) to fill up to top_n
        unknown = [t for t in scope if t not in known]
        return (known + unknown)[:top_n]

    # ── History ───────────────────────────────────────────────────────────────

    def get_run_history(self, limit: int = 20) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT run_id, started_at, status, findings_count,
                       coverage_pct, gap_pct, profile
                FROM runs ORDER BY started_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> Dict[str, Any]:
        with self._conn() as c:
            total_runs     = c.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            total_findings = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            persistent_gaps= c.execute(
                "SELECT COUNT(*) FROM gaps WHERE occurrence_count>=2"
            ).fetchone()[0]
            techniques_seen= c.execute(
                "SELECT COUNT(DISTINCT technique_id) FROM learning"
            ).fetchone()[0]
        return {
            "total_runs":      total_runs,
            "total_findings":  total_findings,
            "persistent_gaps": persistent_gaps,
            "techniques_seen": techniques_seen,
            "db_path":         str(self.db_path),
        }

    def clear(self) -> None:
        """Reset all memory. Irreversible."""
        with self._conn() as c:
            for table in ("runs", "findings", "gaps", "learning"):
                c.execute(f"DELETE FROM {table}")

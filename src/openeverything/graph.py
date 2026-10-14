"""SQLite call-graph store: normalized caller->callee edges per binary.

LanceDB stays the store of record for function rows + vectors; this edge
table exists so multi-hop traversal ("what reaches X", "what does Y call")
runs as one recursive CTE instead of N filtered LanceDB queries. Edges are
keyed by the extractor's unique function names, including namespaces and
address suffixes when required to distinguish overloads.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS edges (
    binary_sha256 TEXT NOT NULL,
    caller TEXT NOT NULL,
    callee TEXT NOT NULL,
    PRIMARY KEY (binary_sha256, caller, callee)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_edges_callee ON edges (binary_sha256, callee);
"""


class GraphStore:
    def __init__(self, db_path: Path | None = None):
        path = db_path or config.GRAPH_DB
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.executescript(_SCHEMA)
        self._savepoint = 0

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self):
        """Group graph writes, including nested add/drop calls, for rollback."""
        self._savepoint += 1
        name = f"oe_write_{self._savepoint}"
        self._conn.execute(f"SAVEPOINT {name}")
        try:
            yield
            self._conn.execute(f"RELEASE SAVEPOINT {name}")
        except BaseException:
            self._conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
            self._conn.execute(f"RELEASE SAVEPOINT {name}")
            raise

    def add_edges(
        self, binary_sha256: str, edges: Iterable[tuple[str, str]]
    ) -> None:
        with self.transaction():
            self._conn.executemany(
                "INSERT OR IGNORE INTO edges (binary_sha256, caller, callee) "
                "VALUES (?, ?, ?)",
                ((binary_sha256, c, t) for c, t in edges),
            )

    def drop_binary(self, binary_sha256: str) -> int:
        with self.transaction():
            cur = self._conn.execute(
                "DELETE FROM edges WHERE binary_sha256 = ?", (binary_sha256,)
            )
        return cur.rowcount

    def callees(self, binary_sha256: str, name: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT callee FROM edges "
            "WHERE binary_sha256 = ? AND caller = ? ORDER BY callee",
            (binary_sha256, name),
        ).fetchall()
        return [r[0] for r in rows]

    def callers(self, binary_sha256: str, name: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT caller FROM edges "
            "WHERE binary_sha256 = ? AND callee = ? ORDER BY caller",
            (binary_sha256, name),
        ).fetchall()
        return [r[0] for r in rows]

    def reachable(
        self,
        binary_sha256: str,
        name: str,
        direction: str = "callees",
        max_depth: int = 6,
    ) -> list[tuple[str, int]]:
        """Transitive closure from `name`. Returns [(func_name, min_depth)].

        direction="callees" walks what `name` calls; direction="callers"
        walks what reaches `name`. Depth-capped so recursion cycles
        terminate.
        """
        if direction == "callees":
            src, dst = "caller", "callee"
        elif direction == "callers":
            src, dst = "callee", "caller"
        else:
            raise ValueError(f"bad direction: {direction!r}")
        rows = self._conn.execute(
            f"""
            WITH RECURSIVE reach(name, depth) AS (
                SELECT {dst}, 1 FROM edges
                WHERE binary_sha256 = ? AND {src} = ?
                UNION
                SELECT e.{dst}, r.depth + 1
                FROM edges e JOIN reach r ON e.{src} = r.name
                WHERE e.binary_sha256 = ? AND r.depth < ?
            )
            SELECT name, MIN(depth) FROM reach GROUP BY name ORDER BY 2, 1
            """,
            (binary_sha256, name, binary_sha256, max_depth),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

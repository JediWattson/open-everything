"""LanceDB-backed store: one row per function, plus a binaries registry."""

from __future__ import annotations

import time
from contextlib import contextmanager
from pathlib import Path

import lancedb

from . import config
from .models import FunctionRecord


class Store:
    def __init__(self, db_dir: Path | None = None):
        path = db_dir or config.DB_DIR
        path.mkdir(parents=True, exist_ok=True)
        self._db = lancedb.connect(str(path))

    def _table(self):
        return self._db.open_table(config.TABLE_NAME)

    def _binaries(self):
        return self._db.open_table("binaries")

    def indexed_sha(self, sha256: str) -> bool:
        if "binaries" not in self._db.list_tables().tables:
            return False
        rows = (
            self._binaries()
            .search()
            .where(f"binary_sha256 = '{sha256}'")
            .limit(1)
            .to_list()
        )
        return bool(rows)

    def add_functions(self, recs: list[FunctionRecord]) -> None:
        if not recs:
            return
        import pyarrow as pa

        rows = [r.to_row() for r in recs]
        if config.TABLE_NAME in self._db.list_tables().tables:
            table = self._table()
            # Older indexes inferred List(Null) from initially empty lists.
            schema = table.schema
            for name in ("callees", "callers", "strings"):
                field = schema.field(name)
                if pa.types.is_null(field.type.value_type):
                    schema = schema.set(
                        schema.get_field_index(name), field.with_type(pa.list_(pa.string()))
                    )
            if schema != table.schema:
                # Lance cannot alter List(Null) directly. Arrow can cast it;
                # replace the table in one versioned write to preserve rows.
                table.add(table.to_arrow().cast(schema), mode="overwrite")
            table.add(rows)
            return

        vector = next((r.vector for r in recs if r.vector is not None), None)
        dim = len(vector) if vector is not None else config.MODEL_DIMS.get(recs[0].model)
        if dim is None:
            raise ValueError(
                f"unknown dim for model {recs[0].model!r} — add it to "
                "config.MODEL_DIMS or ingest with embedding enabled"
            )
        fields = []
        for name in rows[0]:
            if name == "vector":
                dtype = pa.list_(pa.float32(), dim)
            elif name in ("callees", "callers", "strings"):
                dtype = pa.list_(pa.string())
            elif name in ("is_external", "is_thunk"):
                dtype = pa.bool_()
            elif name == "size":
                dtype = pa.int64()
            else:
                dtype = pa.string()
            fields.append(pa.field(name, dtype))
        self._db.create_table(config.TABLE_NAME, rows, schema=pa.schema(fields))

    @contextmanager
    def preserve_binary(self, sha256: str):
        """Restore this binary's rows if an ingest write raises.

        Snapshots cover both LanceDB tables and leave other binaries alone.
        Extraction and embedding should finish before entering this scope.
        """
        condition = f"binary_sha256 = '{sha256}'"
        tables = self._db.list_tables().tables
        snapshots = {
            name: self._db.open_table(name).search().where(condition).to_arrow()
            if name in tables else None
            for name in (config.TABLE_NAME, "binaries")
        }
        try:
            yield
        except BaseException as original:
            failures = []
            for name, snapshot in snapshots.items():
                try:
                    if name not in self._db.list_tables().tables:
                        if snapshot is not None:
                            self._db.create_table(name, snapshot)
                        continue
                    table = self._db.open_table(name)
                    table.delete(condition)
                    if snapshot is not None and snapshot.num_rows:
                        table.add(snapshot.cast(table.schema))
                    elif snapshot is None and table.count_rows() == 0:
                        self._db.drop_table(name)
                except BaseException as error:
                    failures.append(error)
            if failures:
                raise BaseExceptionGroup(
                    "ingest failed and the previous index could not be fully restored",
                    [original, *failures],
                ) from None
            raise

    def missing_vectors(
        self, binary_sha256: str | None = None, model: str | None = None
    ) -> list[dict]:
        """Rows with vector IS NULL — ingested with --defer-embed."""
        if config.TABLE_NAME not in self._db.list_tables().tables:
            return []
        conds = ["vector IS NULL"]
        if binary_sha256:
            conds.append(f"binary_sha256 = '{binary_sha256}'")
        if model:
            conds.append(f"model = '{model}'")
        return self._table().search().where(" AND ".join(conds)).to_list()

    def set_vector(
        self, name: str, binary_sha256: str, vector: list[float]
    ) -> None:
        self._table().update(
            where=f"name = '{name}' AND binary_sha256 = '{binary_sha256}'",
            values={"vector": vector},
        )

    def register_binary(
        self, sha256: str, name: str, path: str, n_functions: int
    ) -> None:
        row = {
            "binary_sha256": sha256,
            "binary_name": name,
            "path": path,
            "n_functions": n_functions,
            "ingested_at": int(time.time()),
        }
        if "binaries" in self._db.list_tables().tables:
            self._binaries().add([row])
        else:
            self._db.create_table("binaries", [row])

    def search(
        self,
        vector: list[float],
        k: int = 8,
        binary_sha256: str | None = None,
        include_stubs: bool = False,
        model: str | None = None,
    ) -> list[dict]:
        conds = [] if include_stubs else ["is_external = false", "is_thunk = false"]
        if binary_sha256:
            conds.append(f"binary_sha256 = '{binary_sha256}'")
        if model:
            conds.append(f"model = '{model}'")
        q = self._table().search(vector).limit(k)
        if conds:
            q = q.where(" AND ".join(conds), prefilter=True)
        return q.to_list()

    def distinct_models(self) -> set[str]:
        if config.TABLE_NAME not in self._db.list_tables().tables:
            return set()
        rows = self._table().search().select(["model"]).to_list()
        return {r["model"] for r in rows}

    def list_binaries(self) -> list[dict]:
        if "binaries" not in self._db.list_tables().tables:
            return []
        return self._binaries().search().to_list()

    def list_functions(
        self, binary_sha256: str | None = None, limit: int = 500
    ) -> list[dict]:
        q = self._table().search().limit(limit)
        if binary_sha256:
            q = q.where(f"binary_sha256 = '{binary_sha256}'")
        return q.to_list()

    def get_function(self, name: str, binary_sha256: str) -> dict | None:
        rows = (
            self._table()
            .search()
            .where(f"name = '{name}' AND binary_sha256 = '{binary_sha256}'")
            .limit(1)
            .to_list()
        )
        return rows[0] if rows else None

    def drop_binary(self, sha256: str) -> int:
        n = 0
        if config.TABLE_NAME in self._db.list_tables().tables:
            t = self._table()
            n = len(
                t.search()
                .where(f"binary_sha256 = '{sha256}'")
                .select(["name"])
                .to_list()
            )
            t.delete(f"binary_sha256 = '{sha256}'")
        if "binaries" in self._db.list_tables().tables:
            self._binaries().delete(f"binary_sha256 = '{sha256}'")
        return n

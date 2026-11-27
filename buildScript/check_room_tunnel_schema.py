"""Check generated Room 7 schema and preservation of Room 6 data with SQLite.

This is a host-side structural check, not an Android instrumentation test.
Run from the repository root after Room generated app/schemas/.../7.json.
"""

import json
import sqlite3
from pathlib import Path


def check():
    schemas = Path("app/schemas/io.nekohasekai.sagernet.database.SagerDatabase")
    old = json.loads((schemas / "6.json").read_text(encoding="utf-8"))["database"]
    new = json.loads((schemas / "7.json").read_text(encoding="utf-8"))["database"]
    assert old["version"] == 6 and new["version"] == 7
    old_tables = {e["tableName"]: e for e in old["entities"]}
    new_tables = {e["tableName"]: e for e in new["entities"]}
    assert old_tables.keys() == new_tables.keys(), "Existing tables changed"
    expected = {
        "fieldPath": "tunnelBean",
        "columnName": "tunnelBean",
        "affinity": "BLOB",
        "notNull": False,
    }
    for name, before in old_tables.items():
        after = new_tables[name]
        fields = [f for f in after["fields"] if f["columnName"] != "tunnelBean"]
        assert fields == before["fields"], f"Existing columns changed: {name}"
        additions = [f for f in after["fields"] if f["columnName"] == "tunnelBean"]
        assert additions == ([expected] if name == "proxy_entities" else [])
        for key in ("primaryKey", "indices", "foreignKeys"):
            assert before[key] == after[key], f"{name}: {key} changed"

    with sqlite3.connect(":memory:") as database:
        for name, entity in old_tables.items():
            database.execute(entity["createSql"].replace("${TABLE_NAME}", name))
            values = []
            for field in entity["fields"]:
                affinity = field["affinity"]
                values.append(
                    1 if affinity == "INTEGER"
                    else b"\x00\xffexisting-profile\x80" if affinity == "BLOB"
                    else "existing user value"
                )
            database.execute(
                f'INSERT INTO "{name}" VALUES ({",".join("?" for _ in values)})',
                values,
            )
        snapshots = {
            name: database.execute(f'SELECT * FROM "{name}"').fetchall()
            for name in old_tables
        }
        database.execute("ALTER TABLE `proxy_entities` ADD COLUMN `tunnelBean` BLOB")
        for name, entity in old_tables.items():
            columns = ",".join(f'"{f["columnName"]}"' for f in entity["fields"])
            assert database.execute(
                f'SELECT {columns} FROM "{name}"'
            ).fetchall() == snapshots[name], f"Data changed: {name}"
        assert database.execute(
            "SELECT tunnelBean FROM proxy_entities"
        ).fetchone() == (None,)

        # Compare the migrated table layout against a freshly created v7 DB.
        with sqlite3.connect(":memory:") as fresh:
            for name, entity in new_tables.items():
                fresh.execute(entity["createSql"].replace("${TABLE_NAME}", name))
                assert database.execute(
                    f'PRAGMA table_info("{name}")'
                ).fetchall() == fresh.execute(
                    f'PRAGMA table_info("{name}")'
                ).fetchall(), f"Migration layout differs from v7: {name}"
    print("Room 6->7: only nullable tunnelBean added; existing data preserved")


if __name__ == "__main__":
    check()

import datetime as dt
import pathlib
import sqlite3
import sys
import tempfile
import types
import unittest
from contextlib import closing
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
registry_module = types.ModuleType("Registry")
registry_module.Registry = object
sys.modules.setdefault("Registry", registry_module)

import srum_mcp_query


APPLICATION_RESOURCE_GUID = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
NETWORK_DATA_GUID = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
VFU_GUID = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}"


class FakeTable:
    def __init__(self, column_names):
        self.column_names = column_names


class FakeRecord:
    def __init__(self, values):
        self.values = values

    def value(self, column_name):
        return self.values.get(column_name, "Empty")


class FakeSrumDatabase:
    def __init__(self, db_path, config):
        self.db_path = pathlib.Path(db_path)
        self.config = config
        self.id_lookup = {
            "1": "C:\\Windows\\System32\\cmd.exe",
            "2": "S-1-5-21-test (alice)",
            "3": "S-1-5-21-test (bob)",
            "4": "C:\\Users\\alice\\report.docx",
            "5": "C:\\Users\\bob\\notes.txt",
        }
        self.tables = {
            APPLICATION_RESOURCE_GUID: FakeTable(
                ["TimeStamp", "AppId", "UserId", "ForegroundCycleTime", "BackgroundCycleTime", "ProcessId"]
            ),
            NETWORK_DATA_GUID: FakeTable(["TimeStamp", "AppId", "BytesSent", "BytesRecvd", "L2ProfileId"]),
            VFU_GUID: FakeTable(["TimeStamp", "UserId", "AppId", "FileId", "ProcessId"]),
            "SruDbIdMapTable": FakeTable(["IdIndex", "IdBlob"]),
        }
        self.records = {
            APPLICATION_RESOURCE_GUID: [
                FakeRecord(
                    {
                        "TimeStamp": dt.datetime(2026, 7, 28, 12, 0, 0),
                        "AppId": 1,
                        "UserId": 2,
                        "ForegroundCycleTime": 40,
                        "BackgroundCycleTime": 2,
                        "ProcessId": 4242,
                    }
                ),
                FakeRecord(
                    {
                        "TimeStamp": dt.datetime(2026, 7, 28, 13, 0, 0),
                        "AppId": 1,
                        "UserId": 3,
                        "ForegroundCycleTime": 10,
                        "BackgroundCycleTime": 5,
                        "ProcessId": 7777,
                    }
                ),
            ],
            NETWORK_DATA_GUID: [
                FakeRecord(
                    {
                        "TimeStamp": dt.datetime(2026, 7, 28, 12, 1, 0),
                        "AppId": 1,
                        "BytesSent": 100,
                        "BytesRecvd": 50,
                        "L2ProfileId": 7,
                    }
                )
            ],
            VFU_GUID: [
                FakeRecord(
                    {
                        "TimeStamp": dt.datetime(2026, 7, 28, 12, 5, 0),
                        "UserId": 2,
                        "AppId": 1,
                        "FileId": 4,
                        "ProcessId": 4242,
                    }
                ),
                FakeRecord(
                    {
                        "TimeStamp": dt.datetime(2026, 7, 28, 13, 5, 0),
                        "UserId": 3,
                        "AppId": 1,
                        "FileId": 5,
                        "ProcessId": 7777,
                    }
                ),
            ],
        }

    def get_tables(self):
        return iter(self.tables)

    def get_table(self, table_name):
        return self.tables[table_name]

    def get_records(self, table_name):
        return iter(self.records.get(table_name, []))

    def close(self):
        return None


class SrumMcpQueryTests(unittest.TestCase):
    def test_sqlite_identifier_sanitizes_names(self):
        self.assertEqual("application_resource_usage", srum_mcp_query.sqlite_identifier("Application Resource Usage"))
        self.assertEqual("_123_table", srum_mcp_query.sqlite_identifier("123 table"))
        self.assertEqual("fallback", srum_mcp_query.sqlite_identifier("{}", "fallback"))

    def test_build_column_markups_merges_default_friendly_and_guid(self):
        config = srum_mcp_query.InMemoryConfig(
            {
                "column_markups": {
                    "All Tables": {"AppId": {"translate": "APPID", "width": "100"}},
                    "Application Resource Usage": {"AppId": {"width": "5"}},
                    APPLICATION_RESOURCE_GUID: {"AppId": {"friendly_name": "Application"}},
                }
            }
        )

        markups = srum_mcp_query.build_column_markups(config, APPLICATION_RESOURCE_GUID, "Application Resource Usage")

        self.assertEqual("APPID", markups["AppId"]["translate"])
        self.assertEqual("5", markups["AppId"]["width"])
        self.assertEqual("Application", markups["AppId"]["friendly_name"])

    def test_translate_record_value_uses_id_map(self):
        config = srum_mcp_query.InMemoryConfig({"SRUDbIdMapTable": {"1": "proc.exe"}})

        self.assertEqual("proc.exe", srum_mcp_query.translate_record_value(1, "APPID", config))
        self.assertIsNone(srum_mcp_query.translate_record_value("Empty", "APPID", config))

    def test_prepare_schema_adds_resolved_columns_and_formula_metadata(self):
        schema = srum_mcp_query.prepare_table_schema(
            APPLICATION_RESOURCE_GUID,
            "Application Resource Usage",
            ["AppId", "Total Bytes"],
            {"AppId": {"translate": "APPID"}, "Total Bytes": {"formula": "=sum(A#ROW_NUM#:B#ROW_NUM#)"}},
        )

        columns = {column["source_column"]: column for column in schema["columns"]}
        self.assertEqual("application_resource_usage", schema["sqlite_name"])
        self.assertEqual("appid_resolved", columns["AppId"]["resolved_column"])
        self.assertEqual("=sum(A#ROW_NUM#:B#ROW_NUM#)", columns["Total Bytes"]["formula"])

    def test_mocked_conversion_writes_metadata_enriched_columns_and_queries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = pathlib.Path(temp_dir) / "srum.sqlite3"
            source_path = pathlib.Path(temp_dir) / "SRUDB.dat"
            source_path.write_bytes(b"fake")

            with mock.patch.object(srum_mcp_query, "_load_database_class", return_value=FakeSrumDatabase):
                result = srum_mcp_query.SRUM_to_SQLITE3(
                    str(source_path), str(output_path), engine="dissect", overwrite=True
                )

            self.assertEqual(str(output_path), result)
            with closing(sqlite3.connect(output_path)) as conn:
                conn.row_factory = sqlite3.Row
                tables = {row["display_name"]: row for row in conn.execute("SELECT * FROM srum_tables")}
                self.assertIn("Application Resource Usage", tables)
                self.assertIn("Network Data Usage", tables)

                app_table = tables["Application Resource Usage"]["sqlite_name"]
                row = conn.execute(f'SELECT * FROM "{app_table}"').fetchone()
                self.assertEqual("C:\\Windows\\System32\\cmd.exe", row["appid_resolved"])
                self.assertEqual("S-1-5-21-test (alice)", row["userid_resolved"])

                id_map = dict(conn.execute("SELECT id_index, resolved_value FROM srum_id_map"))
                self.assertEqual("C:\\Windows\\System32\\cmd.exe", id_map["1"])

            cpu_rows = srum_mcp_query.query_top_processes_by_cpu_usage(
                "2026-07-28 00:00:00", "2026-07-29 00:00:00", 1, str(output_path)
            )
            self.assertEqual(42, cpu_rows[0]["cpu_total"])
            all_cpu_rows = srum_mcp_query.query_top_processes_by_cpu_usage(sqlite_path=str(output_path))
            self.assertEqual(2, len(all_cpu_rows))

    def test_user_queries_allow_omitted_time_range(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = pathlib.Path(temp_dir) / "srum.sqlite3"
            source_path = pathlib.Path(temp_dir) / "SRUDB.dat"
            source_path.write_bytes(b"fake")

            with mock.patch.object(srum_mcp_query, "_load_database_class", return_value=FakeSrumDatabase):
                srum_mcp_query.SRUM_to_SQLITE3(str(source_path), str(output_path), engine="dissect", overwrite=True)

            process_rows = srum_mcp_query.query_processes_by_user_in_time_range("alice", sqlite_path=str(output_path))
            file_rows = srum_mcp_query.query_files_by_user_in_time_range("alice", sqlite_path=str(output_path))

            self.assertEqual(["4242"], [row["processid"] for row in process_rows])
            self.assertEqual(["4242"], [row["processid"] for row in file_rows])
            self.assertEqual("S-1-5-21-test (alice)", process_rows[0]["userid_resolved"])
            self.assertEqual("2", file_rows[0]["userid"])

    def test_user_summary_queries_group_processes_and_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = pathlib.Path(temp_dir) / "srum.sqlite3"
            source_path = pathlib.Path(temp_dir) / "SRUDB.dat"
            source_path.write_bytes(b"fake")

            with mock.patch.object(srum_mcp_query, "_load_database_class", return_value=FakeSrumDatabase):
                srum_mcp_query.SRUM_to_SQLITE3(str(source_path), str(output_path), engine="dissect", overwrite=True)

            process_summary = srum_mcp_query.query_process_summary_by_user_in_time_range("alice", sqlite_path=str(output_path))
            file_summary = srum_mcp_query.query_file_summary_by_user_in_time_range("alice", sqlite_path=str(output_path))

            self.assertEqual("C:\\Windows\\System32\\cmd.exe", process_summary[0]["value"])
            self.assertEqual(1, process_summary[0]["row_count"])
            self.assertEqual(84, process_summary[0]["cpu_total"])
            self.assertEqual(["4242"], process_summary[0]["process_ids"])
            self.assertEqual("4", file_summary[0]["value"])
            self.assertEqual(1, file_summary[0]["row_count"])
            self.assertEqual(["4242"], file_summary[0]["process_ids"])

    def test_read_only_query_allows_select_and_blocks_writes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = pathlib.Path(temp_dir) / "srum.sqlite3"
            source_path = pathlib.Path(temp_dir) / "SRUDB.dat"
            source_path.write_bytes(b"fake")

            with mock.patch.object(srum_mcp_query, "_load_database_class", return_value=FakeSrumDatabase):
                srum_mcp_query.SRUM_to_SQLITE3(str(source_path), str(output_path), engine="dissect", overwrite=True)

            result = srum_mcp_query.query_database_read_only(
                'SELECT display_name FROM srum_tables WHERE display_name = ?',
                ["Application Resource Usage"],
                sqlite_path=str(output_path),
            )

            self.assertEqual(1, result["row_count"])
            self.assertEqual("Application Resource Usage", result["rows"][0]["display_name"])
            with self.assertRaises(ValueError):
                srum_mcp_query.query_database_read_only("DROP TABLE srum_tables", sqlite_path=str(output_path))

    def test_explain_database_schema_describes_srum_tables(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = pathlib.Path(temp_dir) / "srum.sqlite3"
            source_path = pathlib.Path(temp_dir) / "SRUDB.dat"
            source_path.write_bytes(b"fake")

            with mock.patch.object(srum_mcp_query, "_load_database_class", return_value=FakeSrumDatabase):
                srum_mcp_query.SRUM_to_SQLITE3(str(source_path), str(output_path), engine="dissect", overwrite=True)

            schema = srum_mcp_query.explain_database_schema(str(output_path))

            tables = {table["display_name"]: table for table in schema["tables"]}
            self.assertIn("Application Resource Usage", tables)
            self.assertIn("Network Data Usage", tables)
            self.assertEqual(2, tables["Application Resource Usage"]["row_count"])
            self.assertIn("resource usage", tables["Application Resource Usage"]["description"])
            self.assertTrue(tables["Application Resource Usage"]["columns"])


if __name__ == "__main__":
    unittest.main()